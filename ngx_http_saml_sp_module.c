
/*
 * Copyright (C) Maxim Dounin
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <lasso.h>

static ngx_int_t ngx_http_auth_request_init(ngx_conf_t *cf);
static char *ngx_http_saml_sp_handler(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_command_t  ngx_http_saml_sp_commands[] = {

    { ngx_string("saml_sp_redirect"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NAX_CONF_TAKE2, // Takes two arguments: SP config and IdP config
      ngx_http_saml_sp,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t ngx_http_saml_sp_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_saml_sp_module = {
    NGX_MODULE_V1,
    &ngx_http_saml_sp_module_ctx,          /* module context */
    ngx_http_saml_sp_commands,             /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_saml_sp_init,                 /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_saml_sp_exit,                 /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_saml_sp_init(ngx_conf_t *cf)
{

}

static ngx_int_t
ngx_http_saml_sp_exit(ngx_conf_t *cf)
{

}

static char *
ngx_http_saml_sp(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{

}
