/*
 * Copyright (C) 2009,2011,2013,2014 Red Hat, Inc.
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <dbus/dbus.h>

#include <talloc.h>

#include "env.h"
#include "log.h"
#include "subproc.h"

#ifndef HAVE_CLEARENV
extern char **environ;
static void
clear_environment(void)
{
	environ = NULL;
}
#else
static void
clear_environment(void)
{
	clearenv();
}
#endif

#define GROW_SIZE 0x2000

struct cm_subproc_state {
	pid_t pid;
	char *msg;
	int fd, count, bufsize, status;
};

/* Start the passed callback in a subprocess, with a pipe that it can use to
 * send data back to us.  If the callback exits, it must do so by calling
 * _exit() or exec(), to avoid calling exit handlers registered by libraries
 * that we use, which will screw us up.  Pretty much every bit of work that we
 * can't do quickly is done this way. */
struct cm_subproc_state *
cm_subproc_start(int (*cb)(int fd,
			   struct cm_store_ca *ca,
			   struct cm_store_entry *entry,
			   void *data),
		 void *parent,
		 struct cm_store_ca *ca,
		 struct cm_store_entry *entry,
		 void *data)
{
	struct cm_subproc_state *state;
	int fds[2];
	long flags;
	char *configdir, *tmpdir, *tmp, *homedir, *bus, *local, *pvt;

	state = talloc_ptrtype(parent, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->fd = -1;
		state->msg = NULL;
		state->status = -1;
		if (pipe(fds) != -1) {
			fflush(NULL);
			state->pid = fork();
			switch (state->pid) {
			case -1:
				syslog(LOG_DEBUG, "fork() error: %s",
				       strerror(errno));
				close(fds[0]);
				close(fds[1]);
				talloc_free(state);
				state = NULL;
				break;
			case 0:
				state->fd = fds[1];
				close(fds[0]);

				tmp = getenv(CM_STORE_CONFIG_DIRECTORY_ENV);
				configdir = (tmp != NULL) ? strdup(tmp) : NULL;
				tmp = getenv("TMPDIR");
				tmpdir = (tmp != NULL) ? strdup(tmp) : NULL;
				homedir = cm_env_home_dir();
				bus = getenv("DBUS_SESSION_BUS_ADDRESS");
				bus = bus ? strdup(bus) : NULL;
				local = cm_env_local_ca_dir();
				local = local ? strdup(local) : NULL;
				pvt = getenv(CERTMONGER_PVT_ADDRESS_ENV);
				pvt = pvt ? strdup(pvt) : NULL;
				clear_environment();
				setenv("HOME", homedir, 1);
				setenv("PATH", _PATH_STDPATH, 1);
				setenv("SHELL", _PATH_BSHELL, 1);
				setenv("TERM", "dumb", 1);
				if (configdir != NULL) {
					setenv(CM_STORE_CONFIG_DIRECTORY_ENV,
					       configdir, 1);
				}
				if (tmpdir != NULL) {
					setenv("TMPDIR", tmpdir, 1);
				}
				if (bus != NULL) {
					setenv("DBUS_SESSION_BUS_ADDRESS", bus,
					       1);
				}
				if (pvt != NULL) {
					setenv(CERTMONGER_PVT_ADDRESS_ENV, pvt,
					       1);
				}
				if (local != NULL) {
					setenv(CM_STORE_LOCAL_CA_DIRECTORY_ENV,
					       local, 1);
				}

				_exit((*cb)(fds[1], ca, entry, data));
				break;
			default:
				state->fd = fds[0];
				flags = fcntl(state->fd, F_GETFL);
				if (fcntl(state->fd, F_SETFL,
					  flags | O_NONBLOCK) != 0) {
					syslog(LOG_DEBUG,
					       "error marking output for "
					       "subprocess non-blocking: %s",
					       strerror(errno));
				}
				close(fds[1]);
				fds[1] = -1;
				break;
			}
		}
	}
	return state;
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
int
cm_subproc_get_fd(struct cm_subproc_state *state)
{
	return state->fd;
}

/* Get the output to-date. */
const char *
cm_subproc_get_msg(struct cm_subproc_state *state, int *length)
{
	if (length != NULL) {
		*length = state->count;
	}
	return state->msg ? state->msg : "";
}

/* Get the exit status. */
int
cm_subproc_get_exitstatus(struct cm_subproc_state *state)
{
	return state->status;
}

/* Clean up when we're done. */
void
cm_subproc_done(struct cm_subproc_state *state)
{
	pid_t pid;

	if (state != NULL) {
		if (state->pid != -1) {
			kill(state->pid, SIGKILL);
			do {
				pid = waitpid(state->pid, &state->status, 0);
				cm_log(4, "Waited for %ld, got %ld.\n",
				       (long) state->pid, (long) pid);
			} while ((pid == -1) && (errno == EINTR));
		}
		if (state->fd != -1) {
			close(state->fd);
		}
		talloc_free(state);
	}
}

/* Check if we're done (return 0), or need to be called again (-1). */
int
cm_subproc_ready(struct cm_subproc_state *state)
{
	ssize_t i, remainder;
	char *tmp;
	int status;
	if (state->pid == -1) {
		return state->status;
	}
	do {
		remainder = state->bufsize - state->count;
		if (remainder <= 0) {
			tmp = talloc_realloc_size(state, state->msg,
						  state->bufsize + GROW_SIZE + 1);
			if (tmp != NULL) {
				state->msg = tmp;
				state->bufsize += GROW_SIZE;
				state->msg[state->bufsize] = '\0';
				remainder = state->bufsize - state->count;
			} else {
				errno = EINTR;
				i = -1;
				break;
			}
		}
		i = read(state->fd, state->msg + state->count, remainder);
		switch (i) {
		case -1:
		case 0:
			break;
		default:
			state->count += i;
			break;
		}
	} while (i > 0);
	if ((i == -1) && ((errno == EAGAIN) || (errno == EINTR))) {
		status = -1;
	} else {
		state->msg[state->count] = '\0';
		close(state->fd);
		state->fd = -1;
		waitpid(state->pid, &state->status, 0);
		state->pid = -1;
		status = 0;
	}
	return status;
}

/* Adapted from oddjob's parse_args(). */
char **
cm_subproc_parse_args(void *parent, const char *cmdline, const char **error)
{
	const char *p;
	char *q, *bigbuf;
	char **argv;
	int sqlevel, dqlevel, escape;
	size_t buffersize, words;

	buffersize = strlen(cmdline) * 3;
	bigbuf = talloc_zero_size(parent, buffersize);

	sqlevel = dqlevel = escape = 0;
	p = cmdline;
	q = bigbuf;
	while (*p != '\0') {
		switch (*p) {
		case '\\':
			if ((dqlevel != 0) || (sqlevel != 0) || escape) {
				*q++ = *p++;
				escape = 0;
			} else {
				escape = 1;
				p++;
			}
			break;
		case '\'':
			switch (sqlevel) {
			case 0:
				if (escape || (dqlevel > 0)) {
					*q++ = *p++;
					escape = 0;
				} else {
					sqlevel = 1;
					p++;
				}
				break;
			case 1:
				sqlevel = 0;
				p++;
				break;
			}
			break;
		case '"':
			switch (dqlevel) {
			case 0:
				if (escape || (sqlevel > 0)) {
					*q++ = *p++;
					escape = 0;
				} else {
					dqlevel = 1;
					p++;
				}
				break;
			case 1:
				dqlevel = 0;
				p++;
				break;
			}
			break;
		case '\r':
		case '\n':
		case '\t':
		case ' ':
			if (escape || (dqlevel > 0) || (sqlevel > 0)) {
				*q++ = *p;
			} else {
				*q++ = '\0';
			}
			p++;
			break;
		default:
			*q++ = *p++;
			break;
		}
	}
	if (error) {
		*error = NULL;
	}
	if (dqlevel > 0) {
		if (error) {
			*error = "Unmatched \"";
		}
		talloc_free(bigbuf);
		return NULL;
	}
	if (sqlevel > 0) {
		if (error) {
			*error = "Unmatched '";
		}
		talloc_free(bigbuf);
		return NULL;
	}
	if (escape) {
		if (error) {
			*error = "Attempt to escape end-of-command";
		}
		talloc_free(bigbuf);
		return NULL;
	}
	p = NULL;
	words = 0;
	for (q = bigbuf; q < bigbuf + buffersize; q++) {
		if (*q != '\0') {
			if (p == NULL) {
				p = q;
			}
		} else {
			if (p != NULL) {
				words++;
				p = NULL;
			}
		}
	}
	argv = talloc_zero_size(parent, sizeof(char*) * (words + 1));
	p = NULL;
	words = 0;
	for (q = bigbuf; q < bigbuf + buffersize; q++) {
		if (*q != '\0') {
			if (p == NULL) {
				p = q;
			}
		} else {
			if (p != NULL) {
				argv[words++] = talloc_strdup(argv, p);
				p = NULL;
			}
		}
	}
	talloc_free(bigbuf);
	return argv;
}

/* Redirect stdio to /dev/null, and mark everything else as close-on-exec,
 * except for perhaps one to three of them that are passed in by number. */
void
cm_subproc_mark_most_cloexec(int fd, int fd2, int fd3)
{
	int i;
	long l;
	if ((fd != STDIN_FILENO) &&
	    (fd2 != STDIN_FILENO) &&
	    (fd3 != STDIN_FILENO)) {
		i = open("/dev/null", O_RDONLY);
		if (i != -1) {
			if (i != STDIN_FILENO) {
				dup2(i, STDIN_FILENO);
				close(i);
			}
		} else {
			close(STDIN_FILENO);
		}
	}
	if ((fd != STDOUT_FILENO) &&
	    (fd2 != STDOUT_FILENO) &&
	    (fd3 != STDOUT_FILENO)) {
		i = open("/dev/null", O_WRONLY);
		if (i != -1) {
			if (i != STDOUT_FILENO) {
				dup2(i, STDOUT_FILENO);
				close(i);
			}
		} else {
			close(STDOUT_FILENO);
		}
	}
	if ((fd != STDERR_FILENO) &&
	    (fd2 != STDERR_FILENO) &&
	    (fd3 != STDERR_FILENO)) {
		i = open("/dev/null", O_WRONLY);
		if (i != -1) {
			if (i != STDERR_FILENO) {
				dup2(i, STDERR_FILENO);
				close(i);
			}
		} else {
			close(STDERR_FILENO);
		}
	}
	for (i = getdtablesize() - 1; i >= 3; i--) {
		if ((i == fd) ||
		    (i == fd2) ||
		    (i == fd3)) {
			continue;
		}
		l = fcntl(i, F_GETFD);
		if (l != -1) {
			if (fcntl(i, F_SETFD, l | FD_CLOEXEC) != 0) {
				cm_log(0, "Potentially leaking FD %d.\n", i);
			}
		}
	}
}
