/*
 * Copyright (C) 2009,2010,2011,2012,2013,2014 Red Hat, Inc.
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

#include "../../src/config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/select.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <talloc.h>
#include <unistd.h>

#include <dbus/dbus.h>

#include "../../src/iterate.h"
#include "../../src/log.h"
#include "../../src/store.h"
#include "../../src/store-int.h"
#include "tools.h"

static void
wait_to_read(int fd)
{
	fd_set rfds;
	struct timeval tv;

	if (fd >= 0) {
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		select(fd + 1, &rfds, NULL, NULL, &tv);
	} else {
		sleep(1);
	}
}

struct cm_context {
	struct cm_store_ca *ca;
	struct cm_store_entry *entry;
};

static struct cm_store_ca *
get_ca_by_index(struct cm_context *cm, int i)
{
	if (i == 0) {
		return cm->ca;
	} else {
		return NULL;
	}
}

static int
get_n_cas(struct cm_context *cm)
{
	return (cm->ca != NULL) ? 1 : 0;
}

static struct cm_store_entry *
get_entry_by_index(struct cm_context *cm, int i)
{
	if (i == 0) {
		return cm->entry;
	} else {
		return NULL;
	}
}

static int
get_n_entries(struct cm_context *cm)
{
	return (cm->entry != NULL) ? 1 : 0;
}

int
main(int argc, char **argv)
{
	struct cm_context *cm;
	enum cm_state old_state;
	int readfd, delay;
	void *parent, *istate;
	char *p, *q, *continue_states, *stop_states, *tmp;
	const char *state;
	enum cm_time when;

	cm_log_set_method(cm_log_stderr);
	cm_log_set_level(3);
	cm_set_fips_from_env();
	parent = talloc_new(NULL);
	cm = talloc_ptrtype(parent, cm);
	if (cm == NULL) {
		return 1;
	}
	memset(cm, 0, sizeof(*cm));
	if (argc > 3) {
		cm->ca = cm_store_files_ca_read(parent, argv[1]);
		if (cm->ca == NULL) {
			printf("Error reading %s: %s.\n", argv[1],
			       strerror(errno));
			return 1;
		}
		cm->entry = cm_store_files_entry_read(parent, argv[2]);
		if (cm->entry == NULL) {
			printf("Error reading %s: %s.\n", argv[2],
			       strerror(errno));
			return 1;
		}
		if ((cm->entry->cm_ca_nickname == NULL) ||
		    (cm->ca->cm_nickname == NULL) ||
		    (strcasecmp(cm->entry->cm_ca_nickname,
				cm->ca->cm_nickname) != 0)) {
			talloc_free(cm->ca);
			cm->ca = NULL;
		}
		continue_states = argv[3];
		stop_states = NULL;
		if ((argc > 4) && (strlen(argv[4]) > 0)) {
			stop_states = argv[4];
			if (strlen(continue_states) == 0) {
				continue_states = NULL;
			}
		}
	} else {
		printf("Specify a CA file and an entry file as the first "
		       "two arguments, a list of continue states as the "
		       "third, and perhaps a list of stop states as the "
		       "fourth.\n");
		return 1;
	}
	old_state = cm->entry->cm_state;
	state = cm_store_state_as_string(cm->entry->cm_state);
	if (cm_iterate_entry_init(cm->entry, &istate) != 0) {
		printf("Error initializing.\n");
		return 1;
	}
	if (old_state != cm->entry->cm_state) {
		printf("%s\n-(RESET)-\n", state);
	}
	old_state = CM_INVALID;
	state = cm_store_state_as_string(cm->entry->cm_state);
	printf("%s\n-START-\n", state);
	fflush(NULL);
	while (cm_iterate_entry(cm->entry, cm->ca, cm,
				get_ca_by_index, get_n_cas,
				get_entry_by_index, get_n_entries,
				NULL, NULL,
				istate, &when, &delay, &readfd) == 0) {
		state = cm_store_state_as_string(cm->entry->cm_state);
		switch (when) {
		case cm_time_now:
			if (cm->entry->cm_state != old_state) {
				printf("%s\n", state);
			} else {
				printf("%s (now)\n", state);
			}
			break;
		case cm_time_soon:
			if (cm->entry->cm_state != old_state) {
				printf("%s\n", state);
			} else {
				printf("%s (soon)\n", state);
			}
			break;
		case cm_time_soonish:
			if (cm->entry->cm_state != old_state) {
				printf("%s\n", state);
			} else {
				printf("%s (soonish)\n", state);
			}
			break;
		case cm_time_delay:
			if (cm->entry->cm_state != old_state) {
				printf("delay=%ld\n%s\n", (long) delay,
				       state);
			} else {
				printf("delay=%ld (again)\n%s (again)\n",
				       (long) delay, state);
			}
			break;
		case cm_time_no_time:
			if (cm->entry->cm_state != old_state) {
				printf("%s\n", state);
			}
			break;
		}
		if ((cm->entry->cm_state == old_state) &&
		    ((when != cm_time_no_time) || (readfd == -1))) {
			/* If we didn't change state, stop. */
			printf("-STUCK- (%d:%ld)\n", when, (long) delay);
			fflush(NULL);
			state = NULL;
			break;
		}
		if (stop_states != NULL) {
			/* Check if this state is in our stop-states list. */
			for (p = stop_states;
			     *p != '\0';
			     p = q + strspn(q, ",")) {
				q = p + strcspn(p, ",");
				tmp = talloc_strndup(parent, p, q - p);
				if (cm->entry->cm_state ==
				    cm_store_state_from_string(tmp)) {
					fflush(NULL);
					talloc_free(tmp);
					break;
				}
				talloc_free(tmp);
			}
			if (*p != '\0') {
				/* We found a match.  Stop here. */
				printf("-STOP-\n");
				fflush(NULL);
				state = NULL;
				break;
			}
		}
		/* Check if this state is in our continue-states list. */
		if (continue_states != NULL) {
			for (p = continue_states;
			     *p != '\0';
			     p = q + strspn(q, ",")) {
				q = p + strcspn(p, ",");
				tmp = talloc_strndup(parent, p, q - p);
				if (cm->entry->cm_state ==
				    cm_store_state_from_string(tmp)) {
					fflush(NULL);
					talloc_free(tmp);
					break;
				}
				talloc_free(tmp);
			}
			/* If we didn't find a match, stop here. */
			if (*p == '\0') {
				printf("-STOP-\n");
				fflush(NULL);
				state = NULL;
				break;
			}
		}
		/* Wait. */
		switch (when) {
		case cm_time_now:
			break;
		case cm_time_soon:
			sleep(CM_DELAY_SOON);
			break;
		case cm_time_soonish:
			sleep(CM_DELAY_SOONISH);
			break;
		case cm_time_delay:
			sleep(delay);
			break;
		case cm_time_no_time:
			wait_to_read(readfd);
			break;
		}
		state = cm_store_state_as_string(cm->entry->cm_state);
		old_state = cm->entry->cm_state;
	}
	if (state != NULL) {
		printf("-ERROR-\n");
		fflush(NULL);
	}
	cm_iterate_entry_done(cm->entry, istate);
	talloc_free(parent);
	return 0;
}
