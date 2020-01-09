/*
 * Copyright (C) 2010,2015 Red Hat, Inc.
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

#ifndef cmsubmith_h
#define cmsubmith_h

struct cm_submit_h_context;
enum cm_submit_h_opt_env_modify {
	cm_submit_h_env_modify_off,
	cm_submit_h_env_modify_on
};
enum cm_submit_h_opt_negotiate {
	cm_submit_h_negotiate_off,
	cm_submit_h_negotiate_on
};
enum cm_submit_h_opt_delegate {
	cm_submit_h_delegate_off,
	cm_submit_h_delegate_on
};
enum cm_submit_h_opt_clientauth {
	cm_submit_h_clientauth_off,
	cm_submit_h_clientauth_on
};
enum cm_submit_h_opt_curl_verbose {
	cm_submit_h_curl_verbose_off,
	cm_submit_h_curl_verbose_on
};
struct cm_submit_h_context *cm_submit_h_init(void *parent,
					     const char *method,
					     const char *uri,
					     const char *args,
					     const char *content_type,
					     const char *accept,
					     const char *cainfo,
					     const char *capath,
					     const char *sslcert,
					     const char *sslkey,
					     const char *sslpass,
					     enum cm_submit_h_opt_negotiate neg,
					     enum cm_submit_h_opt_delegate del,
					     enum cm_submit_h_opt_clientauth cli,
					     enum cm_submit_h_opt_env_modify env,
					     enum cm_submit_h_opt_curl_verbose verbose);
void cm_submit_h_run(struct cm_submit_h_context *ctx);
int cm_submit_h_response_code(struct cm_submit_h_context *ctx);
int cm_submit_h_result_code(struct cm_submit_h_context *ctx);
const char *cm_submit_h_result_code_text(struct cm_submit_h_context *ctx);
const char *cm_submit_h_results(struct cm_submit_h_context *ctx, int *length);
const char *cm_submit_h_result_type(struct cm_submit_h_context *ctx);

#endif
