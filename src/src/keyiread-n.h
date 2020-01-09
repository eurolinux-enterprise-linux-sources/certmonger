/*
 * Copyright (C) 2009,2011,2014,2015 Red Hat, Inc.
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

#ifndef cmkeyireadn_h
#define cmkeyireadn_h

struct cm_keyiread_n_ctx_and_keys {
	PLArenaPool *arena; /* owns this structure */
	NSSInitContext *ctx;
	SECKEYPrivateKey *privkey, *privkey_next;
	SECKEYPublicKey *pubkey, *pubkey_next;
};
struct cm_keyiread_n_ctx_and_keys *cm_keyiread_n_get_keys(struct cm_store_entry *entry,
							  int readwrite);

#endif
