/*
 * Copyright (C) 2009,2010,2011 Red Hat, Inc.
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
#include <stdlib.h>
#include <unistd.h>

#include <nss.h>
#include <pk11pub.h>

#include <openssl/err.h>
#include <openssl/pem.h>

#include <talloc.h>

#include "certsave.h"
#include "certsave-int.h"
#include "log.h"
#include "store.h"
#include "store-int.h"
#include "subproc.h"
#include "util-o.h"

struct cm_certsave_state {
	struct cm_certsave_state_pvt pvt;
	struct cm_subproc_state *subproc;
};

static int
cm_certsave_o_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		   void *userdata)
{
	int status = -1;
	BIO *bio;
	FILE *pem;
	X509 *cert;
	util_o_init();
	bio = BIO_new_mem_buf(entry->cm_cert, strlen(entry->cm_cert));
	if (bio != NULL) {
		cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		if (cert != NULL) {
			pem = fopen(entry->cm_cert_storage_location, "w");
			if (pem != NULL) {
				if (PEM_write_X509(pem, cert) == 0) {
					cm_log(1, "Error saving certificate "
					       "to '%s'.\n",
					       entry->cm_cert_storage_location);
					status = CM_STATUS_INTERNAL;
				} else {
					status = CM_STATUS_SAVED;
				}
				fclose(pem);
			} else {
				status = CM_STATUS_INTERNAL;
			}
			X509_free(cert);
		} else {
			status = CM_STATUS_INTERNAL;
		}
		BIO_free(bio);
	} else {
		status = CM_STATUS_INTERNAL;
	}
	if (status != 0) {
		_exit(status);
	}
	return 0;
}

/* Check if something changed, for example we finished saving the cert. */
static int
cm_certsave_o_ready(struct cm_store_entry *entry,
		    struct cm_certsave_state *state)
{
	return cm_subproc_ready(entry, state->subproc);
}

/* Check if we saved the certificate -- the child exited with status 0. */
static int
cm_certsave_o_saved(struct cm_store_entry *entry,
		    struct cm_certsave_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(entry, state->subproc);
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != CM_STATUS_SAVED)) {
		return -1;
	}
	return 0;
}

/* Check if we failed because the subject was already there with a different
 * nickname. */
static int
cm_certsave_o_conflict_subject(struct cm_store_entry *entry,
			       struct cm_certsave_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(entry, state->subproc);
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != CM_STATUS_SUBJECT_CONFLICT)) {
		return -1;
	}
	return 0;
}

/* Check if we failed because the nickname was already taken by a different
 * subject . */
static int
cm_certsave_o_conflict_nickname(struct cm_store_entry *entry,
			        struct cm_certsave_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(entry, state->subproc);
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != CM_STATUS_NICKNAME_CONFLICT)) {
		return -1;
	}
	return 0;
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_certsave_o_get_fd(struct cm_store_entry *entry,
		     struct cm_certsave_state *state)
{
	return cm_subproc_get_fd(entry, state->subproc);
}

/* Clean up after saving the certificate. */
static void
cm_certsave_o_done(struct cm_store_entry *entry,
		   struct cm_certsave_state *state)
{
	if (state->subproc != NULL) {
		cm_subproc_done(entry, state->subproc);
	}
	talloc_free(state);
}

/* Start writing the certificate from the entry to the configured location. */
struct cm_certsave_state *
cm_certsave_o_start(struct cm_store_entry *entry)
{
	struct cm_certsave_state *state;
	if (entry->cm_cert_storage_type != cm_cert_storage_file) {
		cm_log(1, "Wrong save method: can only save certificates "
		       "to files.\n");
		return NULL;
	}
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.ready = cm_certsave_o_ready;
		state->pvt.get_fd= cm_certsave_o_get_fd;
		state->pvt.saved= cm_certsave_o_saved;
		state->pvt.done= cm_certsave_o_done;
		state->pvt.conflict_subject = cm_certsave_o_conflict_subject;
		state->pvt.conflict_nickname = cm_certsave_o_conflict_nickname;
		state->subproc = cm_subproc_start(cm_certsave_o_main,
						  NULL, entry, NULL);
		if (state->subproc == NULL) {
			talloc_free(state);
			state = NULL;
		}
	}
	return state;
}
