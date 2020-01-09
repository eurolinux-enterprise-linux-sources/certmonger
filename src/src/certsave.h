/*
 * Copyright (C) 2009 Red Hat, Inc.
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

#ifndef cmcertsave_h
#define cmcertsave_h

struct cm_certsave_state;
struct cm_store_entry;

/* Start writing the certificate from the entry to the configured location. */
struct cm_certsave_state *cm_certsave_start(struct cm_store_entry *entry);
struct cm_certsave_state *cm_certsave_n_start(struct cm_store_entry *entry);
struct cm_certsave_state *cm_certsave_o_start(struct cm_store_entry *entry);

/* Check if something changed, for example we finished saving the cert. */
int cm_certsave_ready(struct cm_store_entry *entry,
		      struct cm_certsave_state *state);

/* Get a selectable-for-read descriptor we can poll for status changes. */
int cm_certsave_get_fd(struct cm_store_entry *entry,
		       struct cm_certsave_state *state);

/* Check if we saved the certificate. */
int cm_certsave_saved(struct cm_store_entry *entry,
		      struct cm_certsave_state *state);

/* Clean up after saving the certificate. */
void cm_certsave_done(struct cm_store_entry *entry,
		      struct cm_certsave_state *state);

#endif
