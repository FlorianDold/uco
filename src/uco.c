/*
  Copyright (C) 2016  Florian Dold

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <jansson.h>

/*
Lots of ideas in this code are taken from
Goanna and cde-exec.c
*/


struct ChildInfo {
  pid_t pid;
  int first;
  int in_syscall;
  size_t child_page;
  struct user_regs_struct saved_regs;
  int scratch_injected;
  // Ignore sigstop because we just attached
  int ignore_sigstop;
};


struct ChildInfo *cis;
unsigned int cis_elem;

FILE *outfile;


struct ChildInfo *
ci_get(pid_t pid)
{
  int i;
  int freepos = -1;
  struct ChildInfo new_ci;
  memset(&new_ci, 0, sizeof (struct ChildInfo));
  new_ci.first = 1;
  new_ci.pid = pid;
  for (i = 0; i < cis_elem; i++) {
    if (cis[i].pid == pid) {
      return &cis[i];
    }
    if (cis[i].pid == 0) {
      freepos = i;
    }
  }
  if (-1 == freepos) {
    cis_elem++;
    cis = realloc(cis, cis_elem * sizeof (struct ChildInfo));
    freepos = cis_elem - 1;
  }
  cis[freepos] = new_ci;
  return &cis[freepos];
}


void
ci_del(pid_t pid)
{
  for (int i = 0; i < cis_elem; i++) {
    if (cis[i].pid == pid) {
      cis[i].pid = 0;
      return;
    }
  }
}


void getregs (const struct ChildInfo *ci, struct user_regs_struct *regs) {
  if (0 != ptrace(PTRACE_GETREGS, ci->pid, NULL, regs) < 0) {
    fprintf(stderr, "ptrace getregs failed\n");
    abort();
  }
}

void setregs (const struct ChildInfo *ci, struct user_regs_struct *regs) {
  if (0 != ptrace(PTRACE_SETREGS, ci->pid, NULL, regs) < 0) {
    fprintf(stderr, "ptrace setregs failed\n");
    abort();
  }
}


char
getmem(const struct ChildInfo *ci, size_t addr) {
  return ptrace(PTRACE_PEEKDATA, ci->pid, (void *) addr, NULL);
}


void
setmem(const struct ChildInfo *ci, size_t addr, char v) {
  ptrace(PTRACE_POKEDATA, ci->pid, (void *) addr, (void *) (size_t) v);
}


size_t
target_strlen(struct ChildInfo *ci, size_t target_addr) {
  size_t len = 0;
  while (1) {
    char c = getmem(ci, target_addr + len);
    if (!c)
      break;
    len++;
  }
  return len;
}


char *
target_strdup(struct ChildInfo *ci, size_t target_addr) {
  size_t len;
  char *str;

  len = target_strlen(ci, target_addr);
  str = malloc(len + 1);
  for (size_t i = 0; i < len; i++) {
    str[i] = getmem(ci, target_addr + i);
  }

  str[len] = 0;

  return str;
}


void
target_strput(struct ChildInfo *ci, char *str) {
  unsigned int i;
  for (i = 0; str[i]; i++) {
    setmem(ci, ci->child_page + i, str[i]);
  }
  setmem(ci, ci->child_page + i, 0);
}


void
ensure_scratch(struct ChildInfo *ci, struct user_regs_struct *regs)
{
  switch (regs->orig_rax) {
    case __NR_open:
      break;
    default:
      return;
  }
  if (!ci->scratch_injected) {
    regs->orig_rax = __NR_mmap;
    /* addr */
    regs->rdi = 0;
    /* len */
    regs->rsi = getpagesize();
    /* prot */
    regs->rdx = PROT_READ;
    /* flags */
    regs->r10 = MAP_PRIVATE | MAP_ANONYMOUS;
    /* fd */
    regs->r8 = -1;
    /* offset */
    regs->r9 = 0;

    setregs(ci, regs);

    ci->scratch_injected = 1;
  }
}


void
report(char *fmt, ...)
{
  if (!outfile) {
    return;
  }
  va_list args;

  va_start(args, fmt);
  vfprintf(outfile, fmt, args);
  //vprintf(fmt, args);
  va_end(args);
}


void
handle_syscall_enter(struct ChildInfo *ci)
{
  struct user_regs_struct regs;
  
  getregs(ci, &regs);
  //printf("!! syscall %llu\n", (long long) regs.orig_rax);

  ensure_scratch(ci, &regs);

  switch (regs.orig_rax) {
    case __NR_open:
    {
      char *name = target_strdup(ci, regs.rdi);
      report("opening '%s'\n", name);
      if (0 == strcmp(name, "foo")) {
        target_strput(ci, "bar");
        regs.rdi = ci->child_page;
        setregs(ci, &regs);
      }
      free(name);
    }
    case __NR_execve:
    {
      char *name = target_strdup(ci, regs.rdi);
      report("execve '%s'\n", name);
      free(name);
    }
    break;
    default:
      break;
  }

}


void
handle_syscall_leave(struct ChildInfo *ci)
{
  if (ci->scratch_injected && 0 == ci->child_page) {
    struct user_regs_struct regs;
    getregs(ci, &regs);
    memcpy(&ci->saved_regs, &regs, sizeof (struct user_regs_struct));
    // TODO: is this correct?
    if (0 == regs.rax) {
      fprintf(stderr, "child mmap failed\n");
      abort();
    }
    ci->child_page = regs.rax;
    memcpy(&regs, &ci->saved_regs, sizeof (struct user_regs_struct));
    /* re-execute syscall */
    regs.rip -= 2;
    regs.rax = regs.orig_rax;
    setregs(ci, &regs);
  }
}


int
main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s CONFIG [TARGET ARGS...]\n", argv[0]);
    return -1;
  }

  json_error_t err;
  json_t *config = json_load_file(argv[1], 0, &err);

  if (!config) {
    fprintf(stderr, "bad config\n");
    return 1;
  }

  if (!json_is_object(config)) {
    fprintf(stderr, "bad config\n");
    return 2;
  }

  {
    json_t *j_outfile;
    j_outfile = json_object_get(config, "outfile");
    if (j_outfile) {
      if (!json_is_string (j_outfile)) {
        fprintf(stderr, "bad config (outfile must be a string)\n");
        return 2;
      }
      outfile = fopen(json_string_value(j_outfile), "w");
      if (!outfile) {
        fprintf(stderr, "could not open outfile");
        return 3;
      }
    }
  }

  pid_t pid = fork();

  if (-1 == pid) {
    fprintf(stderr, "fork failed\n");
    abort();
  }

  if (0 == pid) {
    long ret = ptrace(PTRACE_TRACEME, 0, 0, 0);
    if (0 != ret) {
      fprintf(stderr, "PTRACE_TRACEME failed\n");
      return 1;
    }
    kill(getpid(), SIGSTOP);
    int reti = execvp(argv[2], &argv[2]);
    if (-1 == reti) {
      fprintf(stderr, "execvp failed\n");
      return 1;
    }
    abort();
  }

  while (1) {
    pid_t wpid;
    int status;

    /* wait for any child */
    wpid = waitpid(-1, &status, __WALL);
    if (-1 == wpid) {
      switch (errno) {
        case ECHILD:
          report("All children terminated\n");
          goto cleanup;
          break;
        default:
          perror(NULL);
          break;
      }
    }

    struct ChildInfo *ci;
    ci = ci_get (wpid);
    if (ci->first) {
      if (0 != ptrace(PTRACE_SETOPTIONS, wpid, 0,
                      (PTRACE_O_TRACESYSGOOD |
                       PTRACE_O_EXITKILL |
                       PTRACE_O_TRACEFORK |
                       PTRACE_O_TRACECLONE |
                       PTRACE_O_TRACEEXEC))) {
        printf("ptrace SETOPTIONS failed\n");
        return 1;
      }
      report("tracing new process %lu\n", (long) ci->pid);
      ci->first = 0;
      ci->ignore_sigstop = 1;
    }

    if (WIFEXITED(status)) {
      report("Child %u exited with status %u\n", wpid, WEXITSTATUS(status));
    }
    if (WIFSTOPPED(status)) {
      int signum = WSTOPSIG(status);
      siginfo_t siginfo;
      ptrace(PTRACE_GETSIGINFO, wpid, 0, &siginfo);
      if ((status>>16) == PTRACE_EVENT_FORK) {
        report("event fork\n");
        signum = 0;
      } else if ((status>>16) == PTRACE_EVENT_CLONE) {
        report("event clone\n");
        signum = 0;
      } else if ((status>>16) == PTRACE_EVENT_EXEC) {
        report("event exec\n");
        signum = 0;
      } else if (signum == (SIGTRAP | 0x80)) {
        if (ci->in_syscall) {
          ci->in_syscall = 0;
          handle_syscall_leave(ci);
        } else {
          ci->in_syscall = 1;
          handle_syscall_enter(ci);
        }
        signum = 0;
      } else if (signum == SIGSTOP) {
        if (ci->ignore_sigstop) {
          signum = 0;
          ci->ignore_sigstop = 0;
        }
      }
      ptrace(PTRACE_SYSCALL, wpid, 0, (void *) (size_t) signum);
    }
  }

cleanup:

  if (outfile) {
    fclose(outfile);
  }
}

