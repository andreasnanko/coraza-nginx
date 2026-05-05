/*
 * Coraza connector for nginx - LuaJIT FFI interface
 *
 * Exposes the WAF handle for runtime rule reloading from Lua.
 * The swap function atomically replaces the active WAF in the
 * main conf and all location confs, returning the old handle
 * so the caller can free it after in-flight transactions drain.
 */

#include "ngx_http_coraza_common.h"

coraza_waf_t
ngx_http_coraza_ffi_get_main_waf(void)
{
    ngx_http_coraza_main_conf_t *mmcf;

    mmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                                ngx_http_coraza_module);
    if (mmcf == NULL) {
        return 0;
    }

    return mmcf->waf;
}

coraza_waf_t
ngx_http_coraza_ffi_swap_main_waf(coraza_waf_t new_waf)
{
    ngx_http_coraza_main_conf_t *mmcf;
    ngx_http_coraza_conf_t     **loc_confs;
    ngx_uint_t                   i;
    coraza_waf_t                 old_waf;

    mmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                                ngx_http_coraza_module);
    if (mmcf == NULL) {
        return 0;
    }

    old_waf = mmcf->waf;
    mmcf->waf = new_waf;

    loc_confs = mmcf->loc_confs->elts;
    for (i = 0; i < mmcf->loc_confs->nelts; i++) {
        if (loc_confs[i]->waf == old_waf || loc_confs[i]->waf == 0) {
            loc_confs[i]->waf = new_waf;
        }
    }

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                  "coraza: WAF swapped via FFI (old=%uL, new=%uL, rules=%d)",
                  (unsigned long)old_waf, (unsigned long)new_waf,
                  coraza_rules_count(new_waf));

    return old_waf;
}
