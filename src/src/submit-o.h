/*
 * Copyright (C) 2014 Red Hat, Inc.
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

#ifndef cmsubmito_h
#define cmsubmito_h

SECOidTag cm_submit_n_tag_from_nid(int nid);
int cm_submit_n_nid_from_tag(SECOidTag tag);

int cm_submit_o_sign(void *parent, char *csr,
		     X509 *signer, EVP_PKEY *signer_key,
		     const char *hexserial, time_t now, long life,
		     X509 **cert);

#endif
