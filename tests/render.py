"""Render every template the way deploy.py does, against a vars file shaped like a
long-running install (round-tripped values). Usage: render.py <out-dir>"""
import copy
import json
import os
import sys
import glob
import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[0:0] = [os.path.join(REPO, 'src'), REPO]
from fabriclib.common.jinja_env import jinja_env  # noqa: E402  (the same env deploy.py uses)
from fabriclib.dns.reverse_zones import reverse_zones  # noqa: E402
from fabriclib.deploy.service_units import service_units  # noqa: E402

# FABRIC_TEST_TEMPLATES: another templates folder (its lock beside it), e.g. one with published digests pinned
env = jinja_env(os.environ.get('FABRIC_TEST_TEMPLATES') or os.path.join(REPO, 'templates'))

secrets = dict(ca_password='x', rndc_secret='dGVzdC1vbmx5LXJuZGMtc2VjcmV0LTMyLWJ5dGVzISE=',
               keycloak_admin_user='admin', keycloak_admin_password='x', keycloak_db_password='x',
               ad_radius_password='Rr1',
               radius_secrets={'switch1': 'Sw1tchSecretSw1tchSecret', 'ap-old': 'OldApSecretOldApSecret'},
               webui_oidc_secret='OidcSecret1',
               tsig_secrets={'npm': 'bnBtLXRlc3Qtc2VjcmV0LTMyLWJ5dGVzLWxvbmch', 'acme_dns-01': 'YWNtZS10ZXN0LXNlY3JldA==',
                             'dev1': 'ZGV2MS1zZWNyZXQ=', 'lonely': 'bG9uZWx5LXNlY3JldA=='})
user = dict(deploy_base_dir='/opt', domain='lan.j-j.family', hostname='pi-core',
            host_ip='192.168.7.53', lan_cidr='192.168.7.0/24', lan_gateway='192.168.7.1',
            fabric_subnet='10.255.0.0/24', landing_page_cname=None, install_keycloak=True,
            cert_country='US', cert_province='S', cert_city='C', cert_org='O', cert_ou='IT', ca_name='CA',
            project_containers=['nginx', 'step-ca', 'bind9', 'dirsrv', 'keycloak', 'postgres', 'dirsrv'],
            service_dirs=[{'folder': 'dirsrv', 'owner': 'ldap'}, {'folder': 'extra', 'owner': 'root'}],
            # as normalize_tsig_keys leaves them: an NPM-style per-host key and a primary one
            tsig_keys=[{'name': 'npm', 'algorithm': 'hmac-sha256', 'domain': 'lan.j-j.family',
                        'record_types': ['TXT'], 'records': ['npm', 'shelfmark']},
                       {'name': 'acme_dns-01', 'algorithm': 'hmac-sha256', 'domain': 'lan.j-j.family',
                        'record_types': ['TXT'], 'primary': True},
                       {'name': 'dev1', 'algorithm': 'hmac-sha256', 'domain': 'lan.j-j.family', 'record_types': ['TXT']},
                       {'name': 'lonely', 'algorithm': 'hmac-sha256', 'domain': 'lan.j-j.family', 'record_types': ['TXT']}],
            # certbot devices: rights come from the ACL's policy
            bind_acls={'certbot-devices': ['key "dev1"']},
            bind_acl_policies={'certbot-devices': {'domain': 'lan.j-j.family', 'record_types': ['TXT'],
                                                   'records': ['web', 'git']}},
            dns={'dynamic_zone_var': {'zone_authority': True,
                                      'CNAME': [{'name': 'None', 'canonical': 'pi-core'},
                                                {'name': 'calibre', 'canonical': 'nas25-apps'}]}})

# Suites that start real containers override install-specific values
# (deploy path, host IP, ports) with a JSON object in FABRIC_TEST_VARS.
user.update(json.loads(os.environ.get("FABRIC_TEST_VARS", "{}")))

ctx = {**secrets, **user, 'render_date': '2026-01-01'}
PRISTINE = copy.deepcopy(ctx)      # vars.yaml.j2 updates the dns dict it is given in place
v1 = yaml.safe_load(env.get_template('vars.yaml.j2').render(**ctx))
v2 = yaml.safe_load(env.get_template('vars.yaml.j2').render(**{**ctx, **v1}))

# Reverse zones: generated from forward A/AAAA records (deploy.py does the same).
rv = reverse_zones({'domain': 'lan.test', 'host_ip': '192.168.7.53', 'dns': {
    'dynamic_zone_var': {'zone_authority': True,
                         'A': [{'name': '@', 'ip': '192.168.7.53'}, {'name': 'fabric', 'ip': '192.168.7.53'},
                               {'name': 'nas', 'ip': '192.168.7.10'}, {'name': 'lab', 'ip': '10.1.2.3'},
                               {'name': 'cloud', 'ip': '8.8.8.8'}],
                         'AAAA': [{'name': 'nas', 'ip': 'fd12:3456:789a:1::10'}, {'name': 'pub', 'ip': '2001:db8::1'}]},
    'iot.lan.test': {'A': [{'name': 'cam', 'ip': '192.168.7.99'}]},
    '5.168.192.in-addr.arpa': {'A': []},
}})
z = rv['zones']
assert list(z) == ['1.0.0.0.a.9.8.7.6.5.4.3.2.1.d.f.ip6.arpa', '2.1.10.in-addr.arpa', '7.168.192.in-addr.arpa'], list(z)
ptr7 = {r['label']: r['target'] for r in z['7.168.192.in-addr.arpa']}
assert ptr7 == {'10': 'nas.lan.test.', '53': 'fabric.lan.test.', '99': 'cam.iot.lan.test.'}, ptr7
assert [r['label'] for r in z['7.168.192.in-addr.arpa']] == ['10', '53', '99'], 'PTRs sorted numerically'
assert z['1.0.0.0.a.9.8.7.6.5.4.3.2.1.d.f.ip6.arpa'][0] == {
    'label': '0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0', 'target': 'nas.lan.test.', 'ip': 'fd12:3456:789a:1::10',
    'source': 'AAAA nas in lan.test'}, z
assert {s['ip'] for s in rv['skipped']} == {'8.8.8.8', '2001:db8::1'}, 'public addresses get no local reverse zone'
apex = reverse_zones({'domain': 'lan.test', 'dns': {'dynamic_zone_var': {'A': [{'name': '@', 'ip': '192.168.9.1'}]}}})
assert apex['zones']['9.168.192.in-addr.arpa'][0]['target'] == 'lan.test.', 'apex record -> PTR to the zone, not "@."'
full_rev = reverse_zones(v1)
print('reverse zones', list(full_rev['zones']))
diff = {k: (v1.get(k), v2.get(k)) for k in set(v1) | set(v2) if v1.get(k) != v2.get(k)}
assert not diff, diff
print('project_containers', v2['project_containers'])
print('service_dirs', [d['folder'] for d in v2['service_dirs']])
print('install_webui', v2['install_webui'], v2['hostname_mgr'])
print('CNAMEs', [r['name'] for r in v2['dns']['dynamic_zone_var']['CNAME']])

full = {**secrets, **v2, 'reverse_zone_names': list(full_rev['zones'])}
out = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('--') else None
if out:
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, 'vars.yaml'), 'w') as f:
        yaml.safe_dump(v2, f)
for tpl in sorted(env.list_templates()):
    if not tpl.endswith('.j2') or tpl == 'vars.yaml.j2':
        continue
    extra = {}
    if tpl.startswith('bind9/data/zone'):
        extra = dict(zone_name='lan.j-j.family', zone_records=v2['dns']['dynamic_zone_var'])
    if tpl.startswith('bind9/data/reverse'):
        extra = dict(reverse_zone_name='7.168.192.in-addr.arpa', ptr_records=rv['zones']['7.168.192.in-addr.arpa'])
    if tpl.startswith('systemd/'):
        extra = dict(item={'service': 'samba', 'compose': 'samba', 'folder': 'samba', 'requires': []})
    if tpl.startswith('resolver/config/'):     # what dns_filter/deploy_resolver passes beside the vars
        extra = dict(zones=['lan.j-j.family', '7.168.192.in-addr.arpa'], clients=['192.168.7.0/24'],
                     resolver_rndc_secret='c2VjcmV0', groups=[{'name': 'kids', 'match': ['192.168.7.64/27'],
                                                              'rules_zone': 'group-kids.rpz', 'safe_zone': None}],
                     safe_zone=None, client_tls=False, adguard_tls=True, zone='group-x.rpz', what='group x',
                     allow=[], block=[], level='strict', records=[])
    if tpl.startswith('dnsfilter/AdGuardHome'):   # what dns_filter/deploy_adguard passes beside the vars
        extra = dict(adguard_password_hash='$2b$10$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234', tls=True,
                     filters=[{'id': 1, 'url': '/lists/0123456789ab.txt', 'name': 'L "one"', 'enabled': True}],
                     user_rules=["@@||example.org^$client='kids',important"], groups=['kids'],
                     upstreams=['tls://1.1.1.1'], bootstrap=['1.1.1.1'], with_api=True)
    if tpl.endswith('.json.j2'):
        json.loads(env.get_template(tpl).render(**full))
    text = env.get_template(tpl).render(**full, **extra)
    if out:
        dest = os.path.join(out, tpl[:-3])
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        open(dest, 'w', encoding='utf-8').write(text)
    if tpl.endswith(('.yml.j2', '.yaml.j2')):
        yaml.safe_load(text)
zones = env.get_template('bind9/config/named.conf.zones.j2').render(**full)
keys = env.get_template('bind9/config/named.conf.keys.j2').render(**full)
for want in ('grant "npm" name _acme-challenge.npm.lan.j-j.family. TXT;',
             'grant "npm" name _acme-challenge.shelfmark.lan.j-j.family. TXT;',
             'grant "acme_dns-01" subdomain _acme-challenge TXT;'):
    # covers: setting:tsig_keys +
    assert want in zones, f'missing update-policy grant: {want}'
assert 'zonesub' not in zones, 'no key asked for any_name: nothing may get zonesub'
for want in ('grant "dev1" name _acme-challenge.web.lan.j-j.family. TXT;',
             'grant "dev1" name _acme-challenge.git.lan.j-j.family. TXT;'):
    # covers: setting:bind_acl_policies +
    assert want in zones, f'missing ACL-policy grant: {want}'
assert 'grant "lonely"' not in zones, 'a key with no records, policy or any_name must get no update rights'
acl = env.get_template('bind9/config/named.conf.acl.j2').render(**full)
# covers: setting:bind_acls +
assert 'acl "certbot-devices"' in acl and 'key "dev1";' in acl, 'policy ACL not rendered'
assert 'secret "bnBtLXRlc3Qtc2VjcmV0LTMyLWJ5dGVzLWxvbmch";' in keys, 'embedded TSIG secret not rendered'
print('TSIG keys and RFC2136 grants rendered')
# what apply refuses in tsig_keys and bind_acl_policies (deploy/merge_tsig_keys), saying why, the secrets untouched
from fabriclib.common.errors import ValidationError as _VE  # noqa: E402
from fabriclib.deploy.merge_tsig_keys import merge_tsig_keys  # noqa: E402
_tk = user['tsig_keys']
for _field, _bad, _msg in (
        ('tsig_keys', [{'algorithm': 'hmac-sha256'}], 'needs a name'),
        ('tsig_keys', _tk + [dict(_tk[0])], 'invalid or duplicate TSIG key name'),
        ('tsig_keys', [{'name': '../etc'}], 'invalid or duplicate TSIG key name'),
        ('tsig_keys', [{'name': 'k', 'algorithm': 'hmac-whirlpool'}], 'algorithm must be one of'),
        ('tsig_keys', [{'name': 'k', 'record_types': ['TXT; drop']}], 'invalid record_types'),
        ('tsig_keys', [{'name': 'k', 'records': ['web', 'bad host']}], 'invalid record names'),
        ('tsig_keys', [{'name': 'k', 'secret': 'not base64!'}], 'secret is not valid base64'),
        ('bind_acl_policies', {'certbot-devices': {'records': []}}, 'a policy needs records (hosts) or any_name'),
        ('bind_acl_policies', {'bad acl!': {'any_name': True}}, 'invalid ACL name'),
        ('bind_acl_policies', {'certbot-devices': {'records': ['web'], 'domain': 'evil zone'}}, 'invalid domain'),
        ('bind_acl_policies', {'certbot-devices': {'records': ['web'], 'record_types': ['A B']}},
         'invalid record_types')):
    _vars = {**copy.deepcopy(user), _field: _bad}
    _sec = {'tsig_secrets': dict(secrets['tsig_secrets'])}
    try:
        merge_tsig_keys(_vars, _sec)
        raise AssertionError(f'{_field} accepted: {_bad!r}')
    except _VE as e:
        # covers: setting:tsig_keys setting:bind_acl_policies -
        assert _msg in str(e) and _sec['tsig_secrets'] == secrets['tsig_secrets'], (_field, _bad, str(e))
print('tsig_keys and bind_acl_policies: what apply refuses, with the reason, no secret made')

# Web UI at any host name; the certificate page at /certs/ (no certs.<domain> since 0.7.0, 1.5.1.5).
assert v2['hostname_mgr'] == 'fabric.lan.j-j.family' and 'hostname_certs' not in v2 and 'cname_certs' not in v2, v2
custom = yaml.safe_load(env.get_template('vars.yaml.j2').render(**{**copy.deepcopy(PRISTINE), 'webui_hostname': 'Admin.Example.org'}))
# covers: setting:webui_hostname +
assert custom['hostname_mgr'] == 'admin.example.org', custom['hostname_mgr']
names = [r['name'] for r in custom['dns']['dynamic_zone_var']['CNAME']]
assert 'fabric' not in names and 'admin' not in names, f'no CNAME for a web UI outside the domain: {names}'
ngx = env.get_template('nginx/nginx.conf.j2').render(**{**secrets, **custom})
assert 'server_name admin.example.org;' in ngx and 'certs.lan.j-j.family' not in ngx
same = yaml.safe_load(env.get_template('vars.yaml.j2').render(**{**copy.deepcopy(PRISTINE), 'hostname': 'fabric'}))
assert 'fabric' not in [r['name'] for r in same['dns']['dynamic_zone_var']['CNAME']], 'CNAME must not shadow the host A record'
print('web UI host name (default, custom, same as host) rendered; no certs.<domain> server')

# The DC's own name (2.1.6.45, manual 1.6.5.23): dc-<hostname> by default, cut to 15 characters; any name given is
# kept; a host renamed later leaves the DC alone. (An install from before 0.7.0 keeping its host's name went with
# keep_old_install, 2026-10-13: no such install exists, 2.1.6.51, S10.)
from fabriclib.samba.suggested_dc_name import suggested_dc_name  # noqa: E402


def _dc(**over):
    got = yaml.safe_load(env.get_template('vars.yaml.j2').render(**{**copy.deepcopy(PRISTINE), 'ad_domain': 'ad.j-j.family',
                                                                     **over}))
    compose = yaml.safe_load(env.get_template('samba/docker-compose.yml.j2').render(**got))['services']['samba']
    return got['dc_name'], got['hostname_dc'], compose['environment']['HOST_NAME']


assert _dc() == ('dc-pi-core', 'dc-pi-core.ad.j-j.family', 'dc-pi-core') and suggested_dc_name('pi-core') == 'dc-pi-core', _dc()
for host, want in (('Kitchen-Server01', 'dc-kitchen-serv'), ('raspberrypi-4b', 'dc-raspberrypi')):
    assert _dc(hostname=host)[0] == want == suggested_dc_name(host), (host, _dc(hostname=host))
assert _dc(dc_name='DC1') == ('dc1', 'dc1.ad.j-j.family', 'dc1'), _dc(dc_name='DC1')
renamed = yaml.safe_load(env.get_template('vars.yaml.j2').render(**{**copy.deepcopy(PRISTINE), 'ad_domain': 'ad.j-j.family',
                                                                     'dc_name': 'dc-pi-core', 'hostname': 'kitchen'}))
assert renamed['hostname_dc'] == 'dc-pi-core.ad.j-j.family' and {'ip': renamed['host_ip'], 'name': 'kitchen'} in \
    renamed['dns']['dynamic_zone_var']['A'], renamed['dns']['dynamic_zone_var']['A']
print("the DC's own name: dc-<hostname> cut to 15, a given one kept, a renamed host leaves it")

# The id layout (2.1.6.46, manual 1.6.3.17): the root is site 1, a million long; the organisation's groups in its
# built-in range; no hosts range and no uid_range read: a vars file listing them (as one from before 0.7.0 did) is not
# read for the block, which starts at site 1's (keep_old_install, that read it, deleted 2026-10-13: S10).
from fabriclib.samba.id_range import id_range  # noqa: E402
# covers: setting:posix_id_start +
assert (v2['posix_id_start'], v2['posix_id_block'], id_range(v2)) == (1000000, 1000000, '1000000-1999999'), id_range(v2)
gids = {g['name']: g['gidNumber'] for g in v2['ldap_groups']}
assert gids['admins'] == 1040001 and gids['users'] == 1040009 and all(1040001 <= g <= 1040100 for g in gids.values()), gids
assert 'hosts' not in [o['name'] for o in v2['ldap_organizational_units']] \
    and not any('uid_range' in o for o in v2['ldap_organizational_units']), v2['ldap_organizational_units']
old = {**copy.deepcopy(PRISTINE), 'ldap_organizational_units': [
    {'name': 'users', 'parent': 'accounts', 'uid_range': '5001-50000'}, {'name': 'hosts', 'uid_range': '2000-4900'}],
       'ldap_groups': [{'gidNumber': 1100, 'name': 'admins'}, {'gidNumber': 5000, 'name': 'users'}]}
was = yaml.safe_load(env.get_template('vars.yaml.j2').render(**old))
was_gids = {g['name']: g['gidNumber'] for g in was['ldap_groups']}
assert id_range(was) == '1000000-1999999' and was_gids['admins'] == 1100 and was_gids['users'] == 5000 \
    and 'hosts' not in [o['name'] for o in was['ldap_organizational_units']], (id_range(was), was_gids)
assert id_range({'posix_id_range': '2000000-2999999', 'posix_id_start': 1000000}) == '2000000-2999999'
print("id layout: the root's block 1000000-1999999, the organisation's gids from 1040001; a listed uid_range is not "
      "read, listed gids are kept")
doh = ngx[ngx.index('location /dns-query'):]
doh = doh[:doh.index('\n        }')]          # the location block only
assert 'grpc_pass $bind9_doh_backend;' in doh and '"grpc://resolver:8053"' in doh and 'proxy_pass $' not in doh, \
    "DoH goes to the DNS filter over HTTP/2 (grpc_pass) while it is on (1.12.2.16): BIND's DoH speaks HTTP/2 only"
off = yaml.safe_load(env.get_template('vars.yaml.j2').render(**{**copy.deepcopy(PRISTINE), 'dns_filter': 'none'}))
ngx_off = env.get_template('nginx/nginx.conf.j2').render(**{**secrets, **off})
# covers: setting:dns_filter +
assert '"grpc://bind9:' in ngx_off[ngx_off.index('location /dns-query'):], 'DoH goes to BIND with the DNS filter off'
print('DoH: nginx speaks HTTP/2 to the DNS filter (or BIND with it off) (grpc_pass)')
res_ctx = dict(zones=['lan.j-j.family'], clients=['192.168.7.0/24'], resolver_rndc_secret='c2VjcmV0', client_tls=True,
               adguard_tls=True, safe_zone='safesearch-strict.rpz',
               groups=[{'name': 'kids', 'match': ['!192.168.7.70', '192.168.7.64/27'], 'rules_zone': 'group-kids.rpz',
                        'safe_zone': 'safesearch-ytmoderate.rpz'}])
res_conf = env.get_template('resolver/config/named.conf.j2').render(**{**v2, **res_ctx})
kids = res_conf[res_conf.index('view "kids"'):res_conf.index('view "everyone"')]
everyone = res_conf[res_conf.index('view "everyone"'):]
assert 'listen-on port 853 tls "clients"' in res_conf and 'listen-on port 8053 tls none http "doh"' in res_conf \
    and 'match-clients { !192.168.7.70; 192.168.7.64/27; };' in kids, res_conf
# each view on its own: the group's over DoT naming it (its ClientID), everyone's over plain DNS, both to AdGuard
assert f'remote-hostname "kids.filter.{v2["domain"]}"' in res_conf and \
    f'forwarders port 853 tls "group-kids" {{ {v2["ip_adguard"]}; }};' in kids, kids
assert f'forwarders {{ {v2["ip_adguard"]} port 53; }};' in everyone and 'tls "upstream' not in res_conf, everyone
for view in (kids, everyone):        # fabric's zones and the owner's rules in every view (no chained views now)
    assert 'zone "lan.j-j.family" { type forward;' in view and 'zone "owner.rpz"' in view, view
assert kids.index('zone "fabric.rpz";') < kids.index('zone "group-kids.rpz";') < kids.index('zone "owner.rpz";'), kids
assert 'dnssec-validation auto;' in res_conf and 'validate-except { "' in res_conf and 'responselog yes;' in res_conf and 'category responses' in res_conf
assert 'bind-lists' not in res_conf, 'no list in the resolver (1.12.3)'
plain = env.get_template('resolver/config/named.conf.j2').render(**{**v2, **res_ctx, 'adguard_tls': False})
assert 'tls "group-kids"' not in plain and f'forwarders {{ {v2["ip_adguard"]} port 53; }};' in \
    plain[plain.index('view "kids"'):], 'before its certificate the group forwards over plain DNS'
assert 'tls "clients"' not in env.get_template('resolver/config/named.conf.j2').render(
    **{**v2, **res_ctx, 'client_tls': False}), 'no DoT/DoH listeners before the certificate exists'
print("DNS filter: each view forwards to AdGuard Home (a group over DoT naming it), safe search, DoT and DoH "
      "listeners rendered (1.12.2.16, 1.12.3.6)")

# Federation (manual 1.9): the endpoint's vhost, socket mount, CNAME and unit only when it is
# on; a site's organisation suffix comes from org_domain, its local suffix and names from its own.
assert v2['federation_endpoint'] is False and v2['org_domain'] == v2['domain'], (v2['federation_endpoint'], v2['org_domain'])
assert v2['hostname_federation'] == 'federation.lan.j-j.family', v2['hostname_federation']
assert 'federation' not in [r['name'] for r in v2['dns']['dynamic_zone_var']['CNAME']], 'no CNAME while the endpoint is off'
assert 'server_name federation.' not in env.get_template('nginx/nginx.conf.j2').render(**full), 'no vhost while off'
assert '/srv/federation' not in env.get_template('nginx/docker-compose.yml.j2').render(**full), 'no socket mount while off'
fed = yaml.safe_load(env.get_template('vars.yaml.j2').render(**{**copy.deepcopy(PRISTINE), 'federation_endpoint': True}))
# covers: setting:federation_endpoint +
assert 'federation' in [r['name'] for r in fed['dns']['dynamic_zone_var']['CNAME']], 'CNAME for the endpoint'
ngx = env.get_template('nginx/nginx.conf.j2').render(**{**secrets, **fed})
assert 'server_name federation.lan.j-j.family;' in ngx and 'proxy_pass http://unix:/srv/federation/federation.sock:;' in ngx
assert 'limit_req zone=federation' in ngx and 'client_max_body_size 16k;' in ngx, 'the join route is rate- and size-limited'
assert 'federation/run:/srv/federation:ro' in env.get_template('nginx/docker-compose.yml.j2').render(**{**secrets, **fed})
unit = env.get_template('systemd/fabric-federation.service.j2').render(**fed)
assert f"--allow-uid {fed['service_users']['nginx']['uid']}" in unit and 'lib/federation/server.py' in unit, unit
site = yaml.safe_load(env.get_template('vars.yaml.j2').render(**{**copy.deepcopy(PRISTINE), 'domain': 'branch1.lan.j-j.family',
                                                                  'org_domain': 'lan.j-j.family', 'site_name': 'branch1'}))
# covers: setting:org_domain +
assert site['ldap_base_dn'] == v2['ldap_base_dn'] == 'dc=lan,dc=j-j,dc=family', site['ldap_base_dn']
# covers: setting:site_name setting:domain +
assert site['site_name'] == 'branch1' and site['hostname_federation'] == 'federation.branch1.lan.j-j.family'
# a chosen base DN (the root site's install, e.g. dc=lan) is kept as given: it names the organisation
for base in ('dc=lan', 'o=acme,dc=lan'):
    chosen = yaml.safe_load(env.get_template('vars.yaml.j2').render(**{**copy.deepcopy(PRISTINE), 'ldap_base_dn': base}))
    # covers: setting:ldap_base_dn +
    assert chosen['ldap_base_dn'] == base, chosen['ldap_base_dn']
print('federation: endpoint vhost/mount/CNAME/unit only when on; a site shares the organisation suffix')
# DNS links (manual 1.9 M4): none -> no transfers; with links -> keys, transfers, secondaries, delegation
plain = env.get_template('bind9/config/named.conf.zones.j2').render(**full)
assert 'type secondary' not in plain and 'also-notify' not in plain, 'no federation links: no secondaries, no notify'
links = {'children': [{'site': 'lab', 'key': 'fed-lab', 'algorithm': 'hmac-sha256', 'secret': 'c2VjcmV0', 'delegate': True,
                       'label': 'lab', 'domain': 'lab.lan.j-j.family', 'address': '192.168.9.9'}],
         'upstream': {'site': 'hq', 'key': 'fed-pi-core', 'algorithm': 'hmac-sha256', 'secret': 'dXBzdHJlYW0=',
                      'domain': 'hq.example.org', 'address': '192.168.8.8'}}
zones = env.get_template('bind9/config/named.conf.zones.j2').render(**full, federation_links=links)
keys = env.get_template('bind9/config/named.conf.keys.j2').render(**full, federation_links=links)
assert 'allow-transfer { key "fed-lab"; key "fed-pi-core"; };' in zones and 'notify explicit;' in zones, zones[:600]
assert 'zone "lab.lan.j-j.family" {\n    type secondary;\n    primaries { 192.168.9.9 port 53 key "fed-lab"; };' in zones
assert 'zone "hq.example.org" {\n    type secondary;' in zones and 'key "fed-lab" {' in keys and 'key "fed-pi-core" {' in keys
db = env.get_template('bind9/data/zone.j2').render(**full, federation_links=links, zone_name=v2['domain'],
                                                   zone_records=v2['dns']['dynamic_zone_var'])
assert 'lab                     NS      ns.lab.lan.j-j.family.' in db and 'ns.lab                  A       192.168.9.9' in db
print('federation DNS: no links -> no transfers; links -> keys, signed transfers, secondaries, delegation with glue')
# a name of 24 characters or more (a host name may be any DNS label since 0.7.0, 2.1.6.45) is still apart from its
# type: the name was padded to 24 with nothing after it, and BIND read `<name>A` (2.3.1.21.3)
_long = 'averyveryverylonghostname'
_lz = env.get_template('bind9/data/zone.j2').render(**full, federation_links={}, zone_name=v2['domain'], zone_records={
    'A': [{'name': _long, 'ip': '192.0.2.7'}], 'CNAME': [{'name': 'x' * 40, 'canonical': _long}]})
_rz = env.get_template('bind9/data/reverse-zone.j2').render(**full, reverse_zone_name='2.0.192.in-addr.arpa',
                                                            ptr_records=[{'label': 'x' * 30, 'target': 'a.b.'}])
assert f'{_long} A       192.0.2.7' in _lz and f'{"x" * 40} CNAME   {_long}' in _lz and f'{"x" * 30} PTR' in _rz, _lz
print('zone files: a name of 24 characters or more stays apart from its record type')
# Postgres's health probe signs in as Keycloak's own role once OpenBao has it: the bootstrap role is locked then, and a
# probe as it was refused every 10 s (2.3.1.21.4)
_pg = lambda **s: yaml.safe_load(env.get_template('postgres/docker-compose.yml.j2').render(**full, **s))[  # noqa: E731
    'services']['postgres']['healthcheck']['test'][1]
assert _pg() == 'pg_isready -U keycloak -d keycloak' and \
    _pg(keycloak_db_user='keycloak_db') == 'pg_isready -U keycloak_db -d keycloak', (_pg(), _pg(keycloak_db_user='x'))
print("Postgres's health probe: the bootstrap role before the take-over, Keycloak's own after")
# DNS filter (manual 1.12.2): on by default (2.1.12.3) -> the BIND resolver on 53, BIND on 5053 (even when vars.yaml
# had 53), its own account, no capabilities, no requires; off -> BIND keeps the port vars say
assert v2['dns_filter'] == user.get('dns_filter', 'bind') and v2['install_resolver'] is (v2['dns_filter'] == 'bind')
off = yaml.safe_load(env.get_template('vars.yaml.j2').render(**{**copy.deepcopy(PRISTINE), 'dns_filter': 'none',
                                                                 'bind_dns_port': 53}))
# covers: setting:bind_dns_port setting:dns_filter +
assert off['install_resolver'] is False and off['bind_dns_port'] == 53, 'with the filter off the port is what vars say (53)'
kept = yaml.safe_load(env.get_template('vars.yaml.j2').render(**{**copy.deepcopy(PRISTINE), 'dns_filter': 'none',
                                                                  'bind_dns_port': 5053}))
assert kept['bind_dns_port'] == 5053, 'with the filter off a chosen port is kept (a resolver of your own)'
# the default filter with an old install's port 53 (bind_dns_port given: the hardening suite renders with 10053)
dflt = yaml.safe_load(env.get_template('vars.yaml.j2').render(**{**{k: w for k, w in copy.deepcopy(PRISTINE).items()
                                                                    if not k.startswith('dns_filter')},
                                                                 'bind_dns_port': 53}))
res = yaml.safe_load(env.get_template('vars.yaml.j2').render(**{**copy.deepcopy(PRISTINE), 'dns_filter': 'BIND',
                                                                 'bind_dns_port': 53}))
for r in (dflt, res):
    assert r['dns_filter'] == 'bind' and r['install_resolver'] is True and r['bind_dns_port'] == 5053, \
        (r['dns_filter'], r['install_resolver'], r['bind_dns_port'])
# 0.6's AdGuard Home in front is gone (0.7); 0.7.0's behind the resolver has exactly these settings (1.12.3)
# covers: setting:adguard_mem_limit setting:image_adguard setting:ip_adguard +
assert sorted(k for k in dflt if 'adguard' in k or 'oauth2proxy' in k) == ['adguard_mem_limit', 'image_adguard',
                                                                           'ip_adguard'], dflt.keys()
assert 'adguard' not in [r['name'] for r in dflt['dns']['dynamic_zone_var']['CNAME']]
assert res['service_users']['resolver'] == {'uid': 613, 'gid': 613, 'name': 'fabric-resolver'}, res['service_users']
assert res['service_users']['adguard'] == {'uid': 614, 'gid': 614, 'name': 'fabric-adguard'}, res['service_users']
assert 'oauth2proxy' not in res['service_users'], res['service_users']
assert res['ip_resolver'] == '10.255.0.33' and res['ip_adguard'] == '10.255.0.34'
# the resolver's limit is planned with the others (1.2.4.3): its floor, no lists in it; AdGuard Home's too since 0.7.1:
# the budget counts its steady share, its container's limit is 2.5 times that (1.2.4.3.5, 2.1.12.8)
assert res['resolver_mem_limit'] is None and res['memory_plan']['limits']['resolver'] == 128, res['memory_plan']
AG = res['memory_plan']['limits']['adguard']
assert res['adguard_mem_limit'] is None and AG >= 384 and res['memory_plan']['bursts'] == {'adguard': int(AG * 2.5)}     and res['memory_plan']['over_mb'] == int(AG * 2.5) - AG, res['memory_plan']
assert res['dns_filter_lists'] == [{'name': 'AdGuard DNS filter', 'enabled': True,
                                    'url': 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt'}]
assert res['dns_filter_upstreams'][0] == {'address': '1.1.1.1', 'name': 'cloudflare-dns.com'}, res['dns_filter_upstreams']
assert res['image_adguard'].startswith('adguard/adguardhome:') and '@sha256:' in res['image_adguard'], res['image_adguard']
assert 'adguard' not in env.get_template('nginx/nginx.conf.j2').render(**full), 'no AdGuard vhost: its UI is unpublished'
rc = yaml.safe_load(env.get_template('resolver/docker-compose.yml.j2').render(**{**secrets, **res}))['services']
assert list(rc) == ['bind9-resolver'] and rc['bind9-resolver']['cap_drop'] == ['ALL'] and 'cap_add' not in rc['bind9-resolver']
# covers: setting:host_ip +
assert rc['bind9-resolver']['ports'] == [f"{res['host_ip']}:53:53/tcp", f"{res['host_ip']}:53:53/udp",
                                         f"{res['host_ip']}:853:853/tcp"], rc['bind9-resolver']['ports']   # DoT, 1.12.2.16
assert not any('lists' in m for m in rc['bind9-resolver']['volumes']), 'the resolver holds no lists (1.12.3)'
ag = yaml.safe_load(env.get_template('dnsfilter/docker-compose.yml.j2').render(**{**secrets, **res}))['services']
a = ag['adguard-filter']
assert list(ag) == ['adguard-filter'] and 'ports' not in a, 'AdGuard Home publishes nothing (1.12.3.3)'
assert a['user'] == '614:614' and a['cap_drop'] == ['ALL'] and a['cap_add'] == ['NET_BIND_SERVICE'], a
assert a['read_only'] is True and 'no-new-privileges:true' in a['security_opt'], a
assert a['sysctls'] == {'net.ipv4.ip_unprivileged_port_start': 53} and a['mem_limit'] == f'{int(AG * 2.5)}m', a
assert a['networks']['fabric_net']['ipv4_address'] == '10.255.0.34' and f"{res['deploy_base_dir']}/dnsfilter/lists:/lists:ro" in a['volumes']
assert '--no-check-update' in a['command'] and not any('password' in str(x).lower() for x in a['healthcheck']['test'])
agt = env.get_template('dnsfilter/AdGuardHome.yaml.j2')
agx = dict(adguard_password_hash='$2b$10$x', tls=False, filters=[], user_rules=[], groups=[],
           upstreams=['tls://1.1.1.1'], bootstrap=['1.1.1.1'], ip_resolver=res['ip_resolver'],
           domain=res['domain'])
agc = yaml.safe_load(agt.render(**agx, with_api=True))
assert agc['filters'] == [] and agc['user_rules'] == [] and agc['clients']['persistent'] == [], agc['filters']
assert agc['filtering']['blocking_mode'] == 'nxdomain' and agc['querylog']['enabled'] is False
assert agc['statistics']['enabled'] is False and agc['dns']['allowed_clients'] == ['10.255.0.33']
assert agc['tls']['enabled'] is False and agc['schema_version'] == 34 and agc['filtering']['safe_fs_patterns'] == ['/lists/*']
static = yaml.safe_load(agt.render(**agx, with_api=False))
assert not {'filters', 'user_rules'} & set(static) and 'upstream_dns' not in static['dns'], 'the API parts left out'
units_res = {u['service']: u for u in service_units('/opt', res)}
assert units_res['bind9-resolver']['enabled'] and units_res['bind9-resolver']['requires'] == []
assert units_res['adguard-filter']['enabled'] and units_res['adguard-filter']['requires'] == []
assert units_res['adguard-filter']['folder'] == 'dnsfilter' and 'adguard' not in units_res
print('DNS filter: the BIND resolver on 53 and AdGuard Home behind it on fabric_net only, each its own account, '
      'BIND on 5053')
# time (manual 1.13.1): served by default with NTS sources and ntp.<domain>; a record of the user's own named ntp is kept
assert v2['ntp_serve'] is True and v2['ntp_set_clock'] is True and all(x.endswith(' nts') for x in v2['ntp_servers'])
assert 'ntp' in [r['name'] for r in v2['dns']['dynamic_zone_var']['CNAME']]
own = copy.deepcopy(PRISTINE)
own['dns'] = {'dynamic_zone_var': {'zone_authority': True, 'A': [{'name': 'ntp', 'ip': '192.168.4.9'}]}}
own_v = yaml.safe_load(env.get_template('vars.yaml.j2').render(**own))
assert 'ntp' not in [r['name'] for r in own_v['dns']['dynamic_zone_var'].get('CNAME', [])], 'never a CNAME next to an A'
# covers: setting:ntp_servers +
assert yaml.safe_load(env.get_template('vars.yaml.j2').render(**{**copy.deepcopy(PRISTINE), 'ntp_servers': []}))['ntp_servers'] == []
assert 'time-sync.target' in env.get_template('systemd/wrapper.service.j2').render(**{**v2, 'item': {'service': 'x', 'folder': 'x', 'compose': 'x'}})
print('time: served with NTS sources by default, ntp.<domain>, units after time-sync.target, Kea option 42')
# Every image is pinned by digest (design 2.1.14.3): the vars defaults are the lock's refs,
# no compose file or Dockerfile names an image any other way.
import re  # noqa: E402
from fabriclib.common.read_images_lock import read_images_lock  # noqa: E402
lock = read_images_lock(os.path.join(REPO, 'config'))
assert lock and all(re.fullmatch(r'sha256:[0-9a-f]{64}', e['digest']) for e in lock.values()), 'bad images.lock.yaml'
for e in lock.values():
    assert v2[e['var']] == e['ref'], f"{e['var']} default is not the lock's ref: {v2[e['var']]}"
for key, val in v2.items():
    if key.startswith('image_') and isinstance(val, str):
        # image_fabric_*: "" until the lock pins fabric's published image (manual 1.14.3)
        assert '@sha256:' in val or val.startswith('fabric/') and val.endswith(':local') or \
            (key.startswith('image_fabric_') and val == ''), f'{key} not pinned: {val}'
for svc in ('nginx', 'bind9', 'stepca', 'samba', 'keycloak', 'postgres', 'webui', 'openbao', 'fluentbit'):
    dc = yaml.safe_load(env.get_template(f'{svc}/docker-compose.yml.j2').render(**{**secrets, **v2}))
    for name, spec in dc['services'].items():
        ref = ((spec.get('build') or {}).get('args') or {}).get('BASE_IMAGE') or spec.get('image', '')
        assert '@sha256:' in ref or (spec.get('build') and '@sha256:' in spec['build']['args'].get('BASE_IMAGE', '')), \
            f'{svc}/{name}: image not pinned: {ref}'
for df in glob.glob(os.path.join(REPO, 'packaging', 'images', '*', 'Dockerfile')):
    text = open(df).read()
    assert not re.search(r'^ARG BASE_IMAGE=', text, re.M), f'{df}: BASE_IMAGE must have no default'
    assert all(ln.split()[1].startswith('${BASE_IMAGE}') for ln in text.splitlines() if ln.startswith('FROM ')), \
        f'{df}: FROM must be the pinned ${{BASE_IMAGE}}'
print('every image pinned by digest (lock, vars defaults, compose files, Dockerfiles)')

# Fluent Bit (optional log forwarding, 2.1.15.1): verified TLS to every destination, no credential in the file
fb_vars = {**v2, "hostname": "pi-core", "log_forwarding": {"syslog": {"host": "siem.lan", "port": 6514},
                                                          "elastic": {"url": "https://es.lan:9200", "user": "fabric"}}}
fb = yaml.safe_load(env.get_template('fluentbit/fluent-bit.yaml.j2').render(**fb_vars))
outs = {o["name"]: o for o in fb["pipeline"]["outputs"]}
# covers: setting:log_forwarding +
assert set(outs) == {"syslog", "es"} and all(o["tls.verify"] in (True, "on") for o in outs.values()), outs
assert outs["syslog"]["mode"] == "tls" and outs["syslog"]["syslog_format"] == "rfc5424", outs["syslog"]
assert outs["es"]["host"] == "es.lan" and outs["es"]["port"] == 9200 and outs["es"]["http_passwd"] == "${LOG_ELASTIC_PASSWORD}"
assert fb["service"]["storage.path"] == "/buffer" and any(i["name"] == "systemd" for i in fb["pipeline"]["inputs"])
none = yaml.safe_load(env.get_template('fluentbit/fluent-bit.yaml.j2').render(**{**v2, "hostname": "h"}))
assert [o["name"] for o in none["pipeline"]["outputs"]] == ["null"], none
for svc in ('nginx', 'bind9', 'stepca', 'samba', 'keycloak', 'postgres', 'webui', 'openbao'):
    dc = yaml.safe_load(env.get_template(f'{svc}/docker-compose.yml.j2').render(**{**secrets, **v2}))
    assert all(sp.get("logging", {}).get("driver") == "journald" for sp in dc["services"].values()), svc
print('Fluent Bit: verified TLS to syslog and Elasticsearch, password from the environment; containers log to the journal')
# A declared OpenBao audit device must never change (OpenBao then refuses to become
# active on upgrade); new needs get a new device.
hcl = env.get_template('openbao/openbao.hcl.j2').render(**{**secrets, **v2})
assert 'audit "file" "file" {\n  description = "fabric: every request"\n  options {\n    file_path = "/openbao/logs/audit.log"\n  }\n}' in hcl, 'the original audit device changed'
print('OpenBao audit devices: the original one unchanged')
# Kea (optional DHCP, design §5 / 2.1.4.1): configs, the DHCP subzone, the key's rights, input checks
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.dhcp.normalize_dhcp import normalize_dhcp  # noqa: E402
kv = {**v2, "install_kea": True, "kea_ddns_secret": "a2VhLXRlc3Qtc2VjcmV0LTMyLWJ5dGVzLWxvbmchIQ==",
      "dhcp": {"interfaces": ["eth0"], "subnets": [{"subnet": "192.168.7.0/24", "pools": ["192.168.7.100 - 192.168.7.199"],
               "routers": "192.168.7.1", "reservations": [{"mac": "AA-BB-CC-00-11-22", "ip": "192.168.7.20",
                                                           "hostname": "printer"}]}]}}
kv["dhcp"] = normalize_dhcp(kv)
assert kv["dhcp"]["subnets"][0]["reservations"][0]["mac"] == "aa:bb:cc:00:11:22"


def kea_json(name):
    text = env.get_template(f"kea/{name}.j2").render(**kv)
    return json.loads("\n".join(ln for ln in text.splitlines() if not ln.strip().startswith("//")))


k4 = kea_json("kea-dhcp4.conf")["Dhcp4"]
sn = k4["subnet4"][0]
# covers: setting:dhcp +
assert sn["pools"] == [{"pool": "192.168.7.100 - 192.168.7.199"}] and sn["reservations"][0]["ip-address"] == "192.168.7.20"
assert k4["ddns-qualifying-suffix"] == "dhcp.lan.j-j.family." and k4["ddns-conflict-resolution-mode"] == "check-with-dhcid"
assert k4["control-socket"]["socket-name"].startswith("/var/run/kea/") and k4["interfaces-config"]["interfaces"] == ["eth0"]
# time (manual 1.13.1): Kea hands out this host's chrony (option 42) unless dhcp.ntp says otherwise
assert {"name": "ntp-servers", "data": kv["host_ip"]} in k4["option-data"], k4["option-data"]
kv["dhcp"] = {**kv["dhcp"], "ntp": ["192.168.7.2", "192.168.7.3"]}
assert {"name": "ntp-servers", "data": "192.168.7.2, 192.168.7.3"} in kea_json("kea-dhcp4.conf")["Dhcp4"]["option-data"]
kv["dhcp"] = {**kv["dhcp"], "ntp": []}
assert "ntp-servers" not in str(kea_json("kea-dhcp4.conf")["Dhcp4"]["option-data"]), "dhcp.ntp [] hands out none"
kv["dhcp"] = {k: x for k, x in kv["dhcp"].items() if k != "ntp"}
try:
    normalize_dhcp({**kv, "dhcp": {**kv["dhcp"], "ntp": ["time.example"]}})
    raise AssertionError("dhcp.ntp must be IPv4 addresses")
except ValidationError:
    pass
d2 = kea_json("kea-dhcp-ddns.conf")["DhcpDdns"]
assert d2["forward-ddns"]["ddns-domains"][0]["name"] == "dhcp.lan.j-j.family." and d2["tsig-keys"][0]["name"] == "kea-ddns"
zones = env.get_template('bind9/config/named.conf.zones.j2').render(**{**secrets, **kv, "tsig_keys": [], "tsig_secrets": {}})
dz = zones[zones.index('zone "dhcp.lan.j-j.family"'):]
dz = dz[:dz.index("};\n};") + 5]
assert 'grant "kea-ddns" zonesub A AAAA DHCID;' in dz and dz.count("grant") == 1, dz
keys = env.get_template('bind9/config/named.conf.keys.j2').render(**{**secrets, **kv, "tsig_keys": [], "tsig_secrets": {}})
assert 'key "kea-ddns"' in keys and kv["kea_ddns_secret"] in keys
parent = env.get_template('bind9/data/zone.j2').render(**{**secrets, **kv, "zone_name": "lan.j-j.family",
                                                        "zone_records": kv["dns"]["dynamic_zone_var"]})
assert re.search(r"^dhcp\s+NS\s+ns\.lan\.j-j\.family\.$", parent, re.M), "no delegation of the DHCP subzone"
nokea = env.get_template('bind9/config/named.conf.zones.j2').render(**{**secrets, **v2, "tsig_keys": [], "tsig_secrets": {}})
# covers: setting:install_kea +
assert "dhcp.lan.j-j.family" not in nokea, "no DHCP subzone without Kea"
# covers: setting:dhcp -
for bad, msg in ((lambda d: d["subnets"][0].update(pools=["192.168.8.1 - 192.168.8.9"]), "inside"),
                 (lambda d: d["subnets"][0]["reservations"][0].update(ip="192.168.7.150"), "outside its pools"),
                 (lambda d: d.update(interfaces=[]), "interface"),
                 (lambda d: d["subnets"][0].update(pools=["192.168.7.50 - 192.168.7.60"]), "inside a DHCP pool")):
    d = copy.deepcopy(kv["dhcp"])
    bad(d)
    vv = {**kv, "dhcp": d, "dns": {"dynamic_zone_var": {"A": [{"name": "nas", "ip": "192.168.7.53"}]}}}
    try:
        normalize_dhcp(vv)
        raise AssertionError(f"not refused: {msg}")
    except ValidationError as e:
        assert msg in str(e), (msg, str(e))
# networks beyond the host's LAN (2.1.10.3-5, manual 1.10.3): a lab on a second interface, a guest subnet behind a relay
import ipaddress  # noqa: E402

from fabriclib.dhcp.client_networks import client_networks  # noqa: E402
from fabriclib.dhcp.place_subnets import place_subnets  # noqa: E402
from fabriclib.security.apply_docker_firewall import _rules as docker_rules  # noqa: E402
# fabric's LAN address in this block is the PRISTINE LAN's (the hardening suite renders with host_ip 127.0.0.1)
kv_any_host, kv = kv, {**kv, "host_ip": "192.168.7.53"}
nets = {"eth0": [ipaddress.ip_interface(f"{kv['host_ip']}/24")], "eth1": [ipaddress.ip_interface("10.20.0.10/24")]}
lab = {**kv, "dhcp": normalize_dhcp({**kv, "dhcp": {"interfaces": ["eth0", "eth1"], "subnets": [
    kv["dhcp"]["subnets"][0],
    {"subnet": "10.20.0.0/24", "pools": ["10.20.0.100 - 10.20.0.199"]},
    {"subnet": "10.30.0.0/24", "pools": ["10.30.0.100 - 10.30.0.199"], "access": "guest", "relay": "10.30.0.1"}]}})}
lab["dhcp"] = place_subnets(lab["dhcp"], kv["host_ip"], nets)
placed = {s["subnet"]: (s.get("interface"), s["server"]) for s in lab["dhcp"]["subnets"]}
assert placed == {"192.168.7.0/24": ("eth0", kv["host_ip"]), "10.20.0.0/24": ("eth1", "10.20.0.10"),
                  "10.30.0.0/24": (None, kv["host_ip"])}, placed
try:
    place_subnets({**lab["dhcp"], "interfaces": ["eth9"]}, kv["host_ip"], nets)
    raise AssertionError("not refused: an interface the host lacks")
except ValidationError as e:
    assert "no interface 'eth9'" in str(e), str(e)
relayed = place_subnets({**lab["dhcp"], "subnets": [{"subnet": "10.40.0.0/24", "pools": ["10.40.0.10 - 10.40.0.20"],
                                                     "id": 9}]}, kv["host_ip"], nets)
assert relayed["subnets"][0]["server"] == kv["host_ip"] and "interface" not in relayed["subnets"][0],     "a subnet on no served interface is relayed, served from host_ip"
for bad, msg in (({"access": "staff"}, "access is full"), ({"relay": "not-an-ip"}, "relay")):
    try:
        normalize_dhcp({**kv, "dhcp": {"interfaces": ["eth0"], "subnets": [
            {"subnet": "10.30.0.0/24", "pools": ["10.30.0.100 - 10.30.0.199"], **bad}]}})
        raise AssertionError(f"not refused: {msg}")
    except ValidationError as e:
        assert msg in str(e), (msg, str(e))
served = client_networks(lab)
assert served == {"full": ["192.168.7.0/24", "10.20.0.0/24"], "guest": ["10.30.0.0/24"],
                  "full_addrs": [kv["host_ip"], "10.20.0.10"], "guest_addrs": [kv["host_ip"]]}, served
lab["dhcp_served"] = served
k4 = json.loads("\n".join(ln for ln in env.get_template("kea/kea-dhcp4.conf.j2").render(**lab).splitlines()
                          if not ln.strip().startswith("//")))["Dhcp4"]
by = {s["subnet"]: s for s in k4["subnet4"]}
assert {"name": "domain-name-servers", "data": "10.20.0.10"} in by["10.20.0.0/24"]["option-data"] \
    and {"name": "ntp-servers", "data": "10.20.0.10"} in by["10.20.0.0/24"]["option-data"], "the lab is told 10.20.0.10"
assert not any(o["name"] in ("domain-name-servers", "ntp-servers") for o in by["192.168.7.0/24"]["option-data"]), \
    "the LAN keeps the global options (host_ip)"
assert by["10.30.0.0/24"]["relay"] == {"ip-addresses": ["10.30.0.1"]} and "relay" not in by["10.20.0.0/24"]
assert {"name": "classless-static-route", "data": f"{kv['host_ip']}/32 - 10.20.0.10"} in by["10.20.0.0/24"]["option-data"], \
    "the lab gets a route to host_ip (fabric's names) through fabric's address there"
assert not any(o["name"] == "classless-static-route" for o in by["192.168.7.0/24"]["option-data"]
               + by["10.30.0.0/24"]["option-data"]), "the LAN and a relayed subnet reach host_ip already"
routed = place_subnets(normalize_dhcp({**kv, "dhcp": {"interfaces": ["eth1"], "subnets": [
    {"subnet": "10.20.0.0/24", "pools": ["10.20.0.100 - 10.20.0.199"], "routers": "10.20.0.1"}]}}), kv["host_ip"], nets)
r4 = json.loads("\n".join(ln for ln in env.get_template("kea/kea-dhcp4.conf.j2").render(**{**lab, "dhcp": routed})
                          .splitlines() if not ln.strip().startswith("//")))["Dhcp4"]["subnet4"][0]["option-data"]
assert {"name": "classless-static-route", "data": f"{kv['host_ip']}/32 - 10.20.0.10, 0.0.0.0/0 - 10.20.0.1"} in r4, \
    "with a router, its default route rides in option 121 too (RFC 3442)"
k4dns = json.loads("\n".join(ln for ln in env.get_template("kea/kea-dhcp4.conf.j2").render(
    **{**lab, "dhcp": {**lab["dhcp"], "dns": ["10.20.0.53"]}}).splitlines() if not ln.strip().startswith("//")))
assert not any(o["name"] == "domain-name-servers" for s in k4dns["Dhcp4"]["subnet4"] for o in s["option-data"]), \
    "dhcp.dns names the DNS server for every subnet"
rc = yaml.safe_load(env.get_template("resolver/docker-compose.yml.j2").render(**{**lab, "install_resolver": True}))
rports = next(iter(rc["services"].values()))["ports"]
assert {"10.20.0.10:53:53/udp", "10.20.0.10:853:853/tcp", f"{kv['host_ip']}:53:53/udp"} <= set(rports), rports
nports = yaml.safe_load(env.get_template("nginx/docker-compose.yml.j2").render(**lab))["services"]["nginx"]["ports"]
assert "10.20.0.10:443:443" in nports and nports.count(f"{kv['host_ip']}:443:443") == 1, nports
kv = kv_any_host                  # the rest takes host_ip as the caller gave it
labvars = yaml.safe_load(env.get_template("vars.yaml.j2").render(**{**lab, "install_kea": True}))
assert {"10.20.0.0/24", "192.168.7.0/24"} <= set(labvars["bind_acls"]["dns-resolvers"]) \
    and "10.30.0.0/24" not in labvars["bind_acls"]["dns-resolvers"], labvars["bind_acls"]
guest = [r for r in docker_rules(["192.168.7.0/24", "10.20.0.0/24"], (), ["10.30.0.0/24"]) if "10.30.0.0/24" in r]
assert sorted(r[r.index("--ctorigdstport") + 1] + "/" + r[r.index("-p") + 1] for r in guest) \
    == ["53/tcp", "53/udp", "853/tcp"], guest
print("DHCP beyond the host's LAN: subnets placed on their interfaces (or a relay), each told fabric's address there, "
      "the resolver and nginx listening on it, guests DNS only")
# reverse DNS for DHCP's clients (2.1.10.7, manual 1.10.3.4)
from fabriclib.dhcp.dhcp_reverse_zones import dhcp_reverse_zones  # noqa: E402
from fabriclib.dns.reverse_zones import reverse_zones  # noqa: E402
lab["dhcp_reverse_zones"] = dhcp_reverse_zones(lab)
assert lab["dhcp_reverse_zones"] == ["0.20.10.in-addr.arpa", "0.30.10.in-addr.arpa", "7.168.192.in-addr.arpa"], \
    lab["dhcp_reverse_zones"]
assert dhcp_reverse_zones({**lab, "dhcp": {**lab["dhcp"], "ddns": False}}) == [], "no DNS registration: no zones"
wide = normalize_dhcp({**kv, "dhcp": {"interfaces": ["eth0"], "subnets": [
    {"subnet": "10.50.0.0/22", "pools": ["10.50.0.200 - 10.50.2.10"]}]}})
assert dhcp_reverse_zones({**kv, "dhcp": wide}) == ["0.50.10.in-addr.arpa", "1.50.10.in-addr.arpa",
                                                    "2.50.10.in-addr.arpa"], "a pool across /24s: each zone"
rz = reverse_zones(lab)["zones"]
assert rz.get("0.20.10.in-addr.arpa") == [], "a DHCP zone with no static record is still generated"
rzf = env.get_template("bind9/data/reverse-zone.j2").render(**{**lab, "reverse_zone_name": "0.20.10.in-addr.arpa",
                                                            "ptr_records": []})
assert re.search(r"^\s+300 ; Negative caching TTL", rzf, re.M), "a DHCP zone caches 'no such name' briefly"
zconf = env.get_template("bind9/config/named.conf.zones.j2").render(
    **{**secrets, **lab, "tsig_keys": [], "tsig_secrets": {}, "reverse_zone_names": list(rz)})
lz = zconf[zconf.index('zone "0.20.10.in-addr.arpa"'):]
lz = lz[:lz.index("\n};") + 3]
assert 'grant "kea-ddns" zonesub PTR DHCID;' in lz, lz
others = [z for z in rz if z not in lab["dhcp_reverse_zones"]]
for z in others:
    oz = zconf[zconf.index(f'zone "{z}"'):]
    assert "kea-ddns" not in oz[:oz.index("\n};")], f"{z} is no DHCP zone: no grant"
dd = json.loads("\n".join(ln for ln in env.get_template("kea/kea-dhcp-ddns.conf.j2").render(**lab).splitlines()
                          if not ln.strip().startswith("//")))["DhcpDdns"]
assert [x["name"] for x in dd["reverse-ddns"]["ddns-domains"]] == [z + "." for z in lab["dhcp_reverse_zones"]], dd
assert all(x["key-name"] == "kea-ddns" for x in dd["reverse-ddns"]["ddns-domains"])
assert json.loads("\n".join(ln for ln in env.get_template("kea/kea-dhcp4.conf.j2").render(**lab).splitlines()
                            if not ln.strip().startswith("//")))["Dhcp4"]["ddns-update-on-renew"] is True
assert json.loads("\n".join(ln for ln in env.get_template("kea/kea-dhcp4.conf.j2").render(**lab).splitlines()
                            if not ln.strip().startswith("//")))["Dhcp4"]["cache-threshold"] == 0.0, \
    "no lease caching: a reused lease would skip the update"
# the DNS filter's groups from DHCP (manual 1.10.3.7): references turned into addresses
from fabriclib.dns_filter.expand_group_clients import expand_group_clients  # noqa: E402
gl = {**lab, "dhcp": {**lab["dhcp"], "subnets": [dict(s) for s in lab["dhcp"]["subnets"]]}}
gl["dhcp"]["subnets"][1].update(name="lab", vlan=20)
# covers: setting:dns_filter_groups +
assert expand_group_clients(["dhcp:lab", "dhcp:10.30.0.0/24", "device:printer", "device:AA:BB:CC:00:11:22",
                             "vlan:20", "192.168.7.77"], "kids", gl) == \
    ["10.20.0.0/24", "10.30.0.0/24", "192.168.7.20", "192.168.7.20", "10.20.0.0/24", "192.168.7.77"]
# covers: setting:dns_filter_groups -
for raw, msg in ((["dhcp:nope"], "no DHCP subnet 'nope'"), (["device:ghost"], "no DHCP reservation 'ghost'"),
                 (["vlan:99"], "no DHCP subnet with VLAN '99'")):
    try:
        expand_group_clients(raw, "kids", gl)
        raise AssertionError(f"not refused: {raw}")
    except ValidationError as e:
        assert msg in str(e), (msg, str(e))
try:
    expand_group_clients(["dhcp:lab"], "kids", {**gl, "install_kea": False})
    raise AssertionError("a reference with DHCP off not refused")
except ValidationError as e:
    assert "DHCP is off" in str(e), str(e)
print("the DNS filter's groups from DHCP: dhcp:, device: and vlan: turned into addresses, unknown ones refused")
print("DHCP's reverse DNS: the pools' zones generated even empty, Kea's key granted PTR and DHCID there only, Kea's "
      "reverse domains, registration again on renewal")
kc = yaml.safe_load(env.get_template('kea/docker-compose.yml.j2').render(**kv))["services"]
assert kc["kea-dhcp4"]["cap_add"] == ["NET_RAW", "NET_BIND_SERVICE"] and kc["kea-dhcp4"]["network_mode"] == "host"
assert kc["kea-ddns"]["user"] == "609:609" and not kc["kea-ddns"].get("cap_add")
if "build" in kc["kea-dhcp4"]:      # built here; a host on fabric's published Kea image pulls it (manual 1.14.3)
    assert kc["kea-dhcp4"]["build"]["args"]["KEA_KEY_FINGERPRINT"] == "9DA570BB192211885E4EB280B16C44CD45514C3C"
else:
    assert "@sha256:" in kc["kea-dhcp4"]["image"] and kc["kea-ddns"]["image"] == kc["kea-dhcp4"]["image"]
print('Kea: configs, the DHCP subzone (A/AAAA/DHCID only, delegated), refusals, two capabilities only')

# FreeRADIUS (802.1X): clients with their secrets, BlastRADIUS protection unless relaxed per client,
# EAP-TLS only with the fabric CA, no session resumption, the policy module, a hardened container
from fabriclib.radius.normalize_radius_clients import normalize_radius_clients  # noqa: E402
rclients, rembedded = normalize_radius_clients([{"name": "Switch1", "address": "192.168.7.2"},
                                                {"name": "ap-old", "address": "192.168.7.16/28",
                                                 "message_authenticator": False, "secret": "OldApSecretOldApSecret"}])
# covers: setting:radius_clients +
assert rclients[0] == {"name": "switch1", "address": "192.168.7.2", "message_authenticator": True}, rclients
assert rembedded == {"ap-old": "OldApSecretOldApSecret"} and "secret" not in rclients[1], "secret must leave vars"
# covers: setting:radius_clients -
for bad in ([{"name": "a", "address": "0.0.0.0/0"}], [{"name": "a", "address": "10.0.0.1"}, {"name": "b", "address": "10.0.0.0/24"}],
            [{"name": "a", "address": "10.0.0.1"}, {"name": "a", "address": "10.0.0.2"}], [{"name": "a b", "address": "10.0.0.1"}],
            [{"name": "a", "address": "10.0.0.1", "secret": "has $ {dollar} x"}], [{"name": "a", "address": "10.0.0.1", "secret": "short"}]):
    try:
        normalize_radius_clients(bad)
        raise AssertionError(f"accepted: {bad}")
    except ValidationError:
        pass
rv_ = {**v2, "install_freeradius": True, "radius_clients": rclients, "radius_secrets": secrets["radius_secrets"]}
clients_conf = env.get_template("freeradius/config/clients.conf.j2").render(**rv_)
assert 'secret = "Sw1tchSecretSw1tchSecret"' in clients_conf and "ipaddr = 192.168.7.16/28" in clients_conf
assert clients_conf.count("require_message_authenticator = yes") == 1 and "require_message_authenticator = no" in clients_conf
eap = env.get_template("freeradius/config/mods/eap.j2").render(**rv_)
assert "default_eap_type = tls" in eap and "ca_file = ${certdir}/ca.pem" in eap and "enable = no" in eap \
    and "virtual_server = fabric-check-eap-tls" in eap and not re.search(r"^\s*(md5|leap|gtc)\s*\{", eap, re.M)
assert "ttls {" in eap, "the default network groups are mapped: EAP-TTLS on"
eap_none = env.get_template("freeradius/config/mods/eap.j2").render(**{**rv_, "radius_people": []})
assert "ttls {" not in eap_none and "peap {" not in eap_none, "no password logins while no group is mapped"
from fabriclib.radius.normalize_radius_people import normalize_radius_people  # noqa: E402
people = normalize_radius_people([{"group": "guests", "vlan": "50", "priority": 60}, {"group": "staff", "vlan": 20}])
# covers: setting:radius_people +
assert people[0]["group"] == "guests" and people[1] == {"group": "staff", "vlan": 20, "priority": 100}, people
# covers: setting:radius_people -
for bad in ([{"group": "staff", "vlan": 5000}], [{"group": "staff"}, {"group": "STAFF"}], [{"group": ""}],
            [{"group": "x", "priority": "high"}]):
    try:
        normalize_radius_people(bad)
        raise AssertionError(f"accepted: {bad}")
    except ValidationError:
        pass
eap_p = env.get_template("freeradius/config/mods/eap.j2").render(**{**rv_, "radius_people": people})
assert "ttls {" in eap_p and "virtual_server = fabric-inner-tunnel" in eap_p and "use_tunneled_reply = yes" in eap_p
assert "peap {" in eap_p and "default_eap_type = mschapv2" in eap_p and "mschapv2 {" in eap_p, eap_p   # S3.3
mschap = env.get_template("freeradius/config/mods/mschap.j2").render(**rv_)
assert "--username=%{mschap:User-Name}" in mschap and "--allow-mschapv2" in mschap and "require_strong = yes" in mschap
frj_p = json.loads(env.get_template("freeradius/config/fabric-radius.json.j2").render(**{**rv_, "radius_people": people}))
assert frj_p["people"] == people, frj_p
frj = json.loads(env.get_template("freeradius/config/fabric-radius.json.j2").render(**rv_))
assert frj["uri"] == f"ldaps://{rv_['ip_fabric_gateway']}:636" and frj["bind_dn"] == f"fabric-radius-{rv_['site_name']}@{rv_['ad_domain']}" \
    and frj["base"] == rv_["ad_base_dn"] and frj["site"] == rv_["site_name"], frj   # the site's DC (S3.2)
fc = yaml.safe_load(env.get_template("freeradius/docker-compose.yml.j2").render(**rv_))["services"]["freeradius"]
assert fc["cap_drop"] == ["ALL"] and not fc.get("cap_add") and fc["read_only"] and fc["user"] == "610:610", fc
base_ = rv_["deploy_base_dir"]
assert {f"{base_}/samba/winbindd:/run/samba/winbindd:ro",
        f"{base_}/samba/data/state/winbindd_privileged:/data/state/winbindd_privileged:ro",
        f"{base_}/samba/data/etc:/etc/samba:ro"} <= set(fc["volumes"]), fc["volumes"]   # PEAP through the DC's winbind
assert fc["ports"] == [f"{v2['host_ip']}:1812:1812/udp", f"{v2['host_ip']}:1813:1813/udp"], fc["ports"]
assert v2["radius_people"] == [{"group": "network-staff", "vlan": None, "priority": 50},
                               {"group": "network-guests", "vlan": None, "priority": 100}], v2["radius_people"]
kept_empty = yaml.safe_load(env.get_template('vars.yaml.j2').render(**{**ctx, **v1, "radius_people": []}))
assert kept_empty["radius_people"] == [], "an empty mapping must stay empty (no defaults brought back)"
assert {"network-staff", "network-guests"} <= {g["name"] for g in v2["ldap_groups"]}
assert not any(g.get("bundle") for g in v2["ldap_groups"] if g["name"] in ("network-staff", "network-guests")),     "the network groups grant no fabric web access"
print("FreeRADIUS: clients (secrets out of vars, bad ones refused), EAP-TLS, EAP-TTLS only for mapped groups, policy lookup, no capabilities")

# each systemd unit waits for its health check by container name: that name
# must be a container_name in its compose template (else start hangs 10 min)
from fabriclib.deploy.service_units import service_units  # noqa: E402
units = [(u["compose"], u["folder"]) for u in service_units("/opt", {})]
assert len(units) >= 8, units
for container, folder in units:
    text = open(os.path.join(REPO, "templates", folder, "docker-compose.yml.j2")).read()
    assert re.search(rf"^\s+container_name: {re.escape(container)}\s*$", text, re.M), (folder, container)
print('every unit waits on a container its compose file defines')
print('all templates rendered')

# every fabricctl module imports (a syntax error there only shows in a full install otherwise)
import importlib  # noqa: E402
import pkgutil  # noqa: E402
import fabriclib  # noqa: E402
for mod in pkgutil.walk_packages(fabriclib.__path__, "fabriclib."):
    if not mod.name.endswith(".cli"):
        importlib.import_module(mod.name)
print('every fabriclib module imports')

# 802.1X guides: the Windows scripts carry the root CA, pin the server by name and root thumbprint,
# and hold a well-formed LAN profile; PowerShell here-strings close at column 0; CRLF; public data only
import subprocess as _sp  # noqa: E402
import tempfile as _tf  # noqa: E402
import xml.etree.ElementTree as _ET  # noqa: E402
from fabriclib.radius.radius_guides import radius_guides  # noqa: E402
with _tf.TemporaryDirectory() as _d:
    _sp.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{_d}/k", "-out", f"{_d}/c",
             "-days", "1", "-subj", "/CN=Guide Root"], check=True, capture_output=True)
    _pem = open(f"{_d}/c").read()
    _sha1 = _sp.run(["openssl", "x509", "-in", f"{_d}/c", "-noout", "-fingerprint", "-sha1"],
                    capture_output=True, text=True, check=True).stdout.split("=", 1)[1].strip().lower().replace(":", " ")
_g = radius_guides({**v2, "radius_clients": rclients}, root_pem=_pem)
for _m, _mode in (("tls", "machine"), ("ttls", "user")):
    _s = _g["windows"][_m]["script"]
    assert "\r\n" in _s and "\n" not in _s.replace("\r\n", ""), "CRLF line ends for Windows"
    _t = _s.replace("\r\n", "\n")
    assert _pem.strip() in _t and _g["server_name"] in _t and _sha1 in _t, (_m, _sha1)
    assert _t.count("@'\n") == 2 and _t.count("\n'@") == 2, "here-strings must open and close on their own lines"
    _xml = _t.split("Set-Content -Path $xml -Encoding Ascii -Value @'\n", 1)[1].split("'@", 1)[0]
    _root = _ET.fromstring(_xml.split("?>", 1)[1])
    assert _root.tag.endswith("LANProfile") and f"<authMode>{_mode}</authMode>" in _xml
    assert "Rr1" not in _t and "Sw1tchSecret" not in _t and "PRIVATE KEY" not in _t, "public data only"
assert "-Pfx" in _g["windows"]["tls"]["script"] and "<Type xmlns=\"http://www.microsoft.com/provisioning/EapCommon\">21<" \
    in _g["windows"]["ttls"]["script"] and "<PAPAuthentication />" in _g["windows"]["ttls"]["script"]
print("802.1X guides: Windows scripts (CA, pinned server, well-formed profiles, CRLF, public data only)")

# every fabricctl command on an install reaches cli.py: manage.sh hands it all its arguments (none: the menu)
_manage = open(os.path.join(REPO, "src", "ux", "cli", "manage.sh")).read()
assert 'exec python3 "$FABRIC_DIR/lib/fabriclib/cli.py" "$@"' in _manage and "set -- --interactive" in _manage
_cli = open(os.path.join(REPO, "src", "fabriclib", "cli.py")).read()
for _flag in ("--mint-certs", "--service-cert", "--render-jinja", "--print", "--interactive", "--apply",
              "--update-containers", "--client-cert", "--keycloak-sync", "--version"):
    assert f'"{_flag}"' in _cli, f"cli.py does not route {_flag}"
print('every fabricctl subcommand and flag reaches cli.py')

# the vars editor turns typed text into YAML values (fabriclib/menu/parse_value.py)
from fabriclib.menu.parse_value import parse_value  # noqa: E402
assert [parse_value(t) for t in ("", "null", "''", "TRUE", "false", "42", "4.2", "eth0")] == \
    [None, None, None, True, False, 42, "4.2", "eth0"]
print('vars editor: typed values parsed (null, booleans, integers, text)')

# sign-in (manual 2.3.6.2.6): the web console asks for a client certificate only with webui_client_cert (2.1.8.2: off by
# default); webui.json tells the web app; the first admin's README follows both
from fabriclib.setup.create_admin import _readme  # noqa: E402
ngx_off = env.get_template('nginx/nginx.conf.j2').render(**{**full, 'install_webui': True})
ngx_on = env.get_template('nginx/nginx.conf.j2').render(**{**full, 'install_webui': True, 'webui_client_cert': True})
assert 'ssl_verify_client optional;' in ngx_off and 'ssl_verify_client on;' not in ngx_off, 'no certificate required by default'
# covers: setting:webui_client_cert +
assert 'ssl_verify_client on;' in ngx_on and 'ssl_client_certificate /etc/nginx/certs/client-ca/ca-bundle.pem;' in ngx_on
assert v2['webui_client_cert'] is False and v2['signin_kerberos'] is False and v2['signin_admin_second_factor'] == 'none'
assert v2['webui_admin_role'] == 'fabric-console-admin', "the admin role is not the first admin's name (2.1.6.33)"
wj = json.loads(env.get_template('webui/webui.json.j2').render(**{**full, 'webui_oidc_secret': 'x'}))
assert wj['client_cert'] is False, wj
kit = {**v2, 'host_ip': '192.168.7.53'}
off_txt, on_txt = _readme(kit, 'jim', 'jim', '/home/jim/fabric-admin'), \
    _readme({**kit, 'webui_client_cert': True, 'signin_admin_second_factor': 'totp'}, 'jim', 'jim', '/x')
assert '.p12' not in off_txt and 'p12-password' not in off_txt and '\n1. First, your computer must find' in off_txt
assert '192.168.7.53 ' + v2['hostname_landing'] in off_txt and 'http://192.168.7.53/certs/' in off_txt, off_txt
assert off_txt.index('find fabric') < off_txt.index('Trust the root CA') < off_txt.index('sign in as'), off_txt
# covers: setting:signin_admin_second_factor +
assert 'jim.p12' in on_txt and '\n4. Import jim.p12' in on_txt and '\n5. Open https://' in on_txt and 'authenticator app (TOTP)' in on_txt
print('sign-in: no client certificate by default (nginx, webui.json, the admin kit); with it, mutual TLS and the .p12')

# landing-page links from DNS records (manual 1.4.2.2, 2.1.4.2): only marked A/AAAA/CNAME records, https with port and
# path, never a wildcard; the zone file is unchanged by the mark; the validator refuses what could break the page
from fabriclib.dns.validate_record import validate_record  # noqa: E402
_host1 = validate_record("A", {"name": "host1", "ip": "192.168.4.21", "link": "on", "link_label": "Proxmox host1",
                               "link_port": "8006"})
assert _host1 == {"name": "host1", "ip": "192.168.4.21", "link": {"label": "Proxmox host1", "port": 8006, "path": None}}
assert "link" not in validate_record("A", {"name": "printer", "ip": "192.168.4.30"})
for _bad in ({"link_label": "<script>"}, {"link_path": "no-slash"}, {"link_path": "/a b"}, {"link_port": "70000"},
             {"link_path": '/"x'}):
    try:
        validate_record("CNAME", {"name": "nas", "target": "nas25", "link": "on", **_bad})
        raise AssertionError(f"accepted {_bad}")
    except ValidationError:
        pass
_zone = copy.deepcopy(v2["dns"])
_zone["dynamic_zone_var"].setdefault("A", []).extend(
    [_host1, {"name": "printer", "ip": "192.168.4.30"},
     {"name": "*.apps", "ip": "192.168.4.40", "link": {"label": "Apps", "port": None, "path": None}}])
_zone["dynamic_zone_var"].setdefault("CNAME", []).append(
    {"name": "nas", "canonical": "nas25", "link": {"label": None, "port": None, "path": "/ui/"}})
_landing = env.get_template('nginx/www/landing/index.html.j2').render(**{**full, 'dns': _zone})
# covers: setting:dns +
assert f'href="https://host1.{v2["domain"]}:8006/"' in _landing and '>Proxmox host1<' in _landing, _landing[-1500:]
assert f'href="https://nas.{v2["domain"]}/ui/"' in _landing and "printer" not in _landing and "Apps" not in _landing
assert _landing.index("This network") < _landing.index(f'nas.{v2["domain"]}') < _landing.index("Proxmox host1"), \
    "sorted by label, whatever its case"
_db = env.get_template('bind9/data/zone.j2').render(**full, federation_links={}, zone_name=v2['domain'],
                                                    zone_records=_zone["dynamic_zone_var"])
assert re.search(r"^host1\s+A\s+192\.168\.4\.21$", _db, re.M) and "8006" not in _db and "Proxmox" not in _db
print('landing links from DNS records: only marked ones, https with port and path; the zone file unchanged (2.1.4.2)')
# the console's record form (2.1.2.22 item 3): one value, filling the type's own field; each type still checked
assert validate_record("A", {"name": "nas", "value": "192.168.4.10"}) == {"name": "nas", "ip": "192.168.4.10"}
assert validate_record("CNAME", {"name": "www", "value": "nas"})["canonical"] == "nas"
assert validate_record("TXT", {"name": "@", "value": "v=spf1 -all"})["text"] == "v=spf1 -all"
assert validate_record("MX", {"name": "@", "value": "mail", "priority": "10"}) == {
    "name": "@", "priority": 10, "exchange": "mail"}
assert validate_record("SRV", {"name": "_sip._tcp", "value": "pbx", "priority": "0", "weight": "5", "port": "5060"})[
    "target"] == "pbx"
for _rt, _form, _why in (("A", {"value": "nas"}, "invalid IPv4"), ("MX", {"value": "mail"}, "priority must be"),
                         ("SRV", {"value": "pbx", "priority": "1", "weight": "1"}, "port must be"),
                         ("TXT", {"value": 'a"b'}, "TXT must be")):
    try:
        validate_record(_rt, {"name": "x", **_form})
        raise AssertionError(f"accepted {_rt} {_form}")
    except ValidationError as _e:
        assert _why in str(_e), (_rt, _e)
print("the record form: one value fills the type's field; priority for MX, priority, weight and port for SRV, "
      "each type checked (2.1.2.22)")
# fabric's own names in the site's zone (2.1.2.22 item 6): every render adds them back, so the console marks them and
# a delete is refused, naming the setting; the admin's own records and other zones are never fabric's. The landing
# page's info is the admin's since 0.7.1 (2.1.4.6): added by the install's first render, never added back
from fabriclib.dns.common.fabric_record import fabric_record  # noqa: E402
_site = v2["dns"]["dynamic_zone_var"]
_info = next(r for r in _site["CNAME"] if r["name"] == "info")
assert _info == {"name": "info", "canonical": v2["hostname"]}, _info
assert fabric_record(v2, "dynamic_zone_var", "CNAME", _info) is None, "info is an ordinary record (2.1.4.6)"
_ca_rec = next(r for r in _site["CNAME"] if r["name"] == "ca")
assert fabric_record(v2, "dynamic_zone_var", "CNAME", _ca_rec) == {"service": "the CA (step-ca)", "setting": "cname_ca"}
assert [r["name"] for r in _site["CNAME"] if not fabric_record(v2, "dynamic_zone_var", "CNAME", r)] == \
    ["calibre", "info"], _site["CNAME"]
# the admin deletes info (or renames it: deleted, added under another name): the next render does not add it back
_gone = copy.deepcopy(v2)
_gone["dns"]["dynamic_zone_var"]["CNAME"] = [r for r in _gone["dns"]["dynamic_zone_var"]["CNAME"] if r["name"] != "info"]
_gone["dns"]["dynamic_zone_var"]["CNAME"].append({"name": "welcome", "canonical": v2["hostname"]})
_v3 = yaml.safe_load(env.get_template('vars.yaml.j2').render(**{**secrets, **_gone, 'render_date': '2026-01-01'}))
_names3 = [r["name"] for r in _v3["dns"]["dynamic_zone_var"]["CNAME"]]
assert "info" not in _names3 and "welcome" in _names3 and _v3["hostname_landing"] == v2["hostname_landing"], _names3
# a repointed info is kept as the admin left it
_moved = copy.deepcopy(v2)
for _r in _moved["dns"]["dynamic_zone_var"]["CNAME"]:
    if _r["name"] == "info":
        _r["canonical"] = "nas25-apps"
_v3 = yaml.safe_load(env.get_template('vars.yaml.j2').render(**{**secrets, **_moved, 'render_date': '2026-01-01'}))
assert [r for r in _v3["dns"]["dynamic_zone_var"]["CNAME"] if r["name"] == "info"] == [
    {"name": "info", "canonical": "nas25-apps"}], _v3["dns"]["dynamic_zone_var"]["CNAME"]
# covers: setting:landing_page_cname +
_fresh = yaml.safe_load(env.get_template('vars.yaml.j2').render(**{**copy.deepcopy(PRISTINE),
                                                                    'landing_page_cname': 'welcome'}))
assert _fresh["hostname_landing"] == f"welcome.{v2['domain']}" and {"name": "welcome", "canonical": v2["hostname"]} \
    in _fresh["dns"]["dynamic_zone_var"]["CNAME"] and "info" not in [
        r["name"] for r in _fresh["dns"]["dynamic_zone_var"]["CNAME"]], _fresh["dns"]["dynamic_zone_var"]["CNAME"]
# the host's own A records are fabric's (an admin's record at another address is not: the hardening suite renders
# with host_ip 127.0.0.1 beside the fixture's pi-core at 192.168.7.53)
_own = [r for r in _site["A"] if r["ip"] == v2["host_ip"]]
assert _own and all(fabric_record(v2, "dynamic_zone_var", "A", r) for r in _own), _site["A"]
_host = {"name": v2["hostname"], "ip": v2["host_ip"]}
assert fabric_record(v2, "dynamic_zone_var", "A", _host)["setting"] == "hostname"
assert fabric_record(v2, "dynamic_zone_var", "CNAME", {"name": "info", "canonical": "nas25"}) is None, \
    "an admin's own record of the same name points elsewhere: theirs"
assert fabric_record(v2, "dynamic_zone_var", "A", {"name": "host1", "ip": "192.168.4.21"}) is None
assert fabric_record(v2, "home.lan", "CNAME", _info) is None, "only the site's zone holds fabric's names"
print("fabric's own names in the site's zone recognised by name and target; the admin's records never (2.1.2.22)")
_ngx = env.get_template('nginx/nginx.conf.j2').render(**full)
# the landing page (2.1.4.3, 2.1.4.6): at /info/ on every name over HTTP (http://<host_ip>/info/), and at / and /info/
# on its names (the host's own name, <domain>, and the zone's aliases of the host: info.<domain> on a new install;
# 2.1.4.8) over HTTP with no redirect and over HTTPS
_land = v2['hostname_landing']
_host_fqdn = (v2['hostname'] + '.' + v2['domain']).lower()
_landing_names = f"server_name {_host_fqdn} {v2['domain']} {_land};"
_blocks = re.split(r"\n    server \{", _ngx)
_info80 = [b for b in _blocks if "listen 80;" in b and _landing_names in b]
assert _land == f"info.{v2['domain']}", _land
assert _info80 and "return 301 https" not in _info80[0].split("location /manual/")[0] \
    and "location /certs/" in _info80[0] and "location /info/" in _info80[0], \
    "the landing names answer on plain HTTP, with the CA files and /info/, without a redirect"
# covers: setting:hostname +
assert not [b for b in _blocks if "$scheme://" + _land in b or f"https://{_land}" in b], \
    "nothing redirects to info.<domain> any more: the admin may rename, repoint or delete it (2.1.4.6)"
_info443 = [b for b in _blocks if "listen 443 ssl;" in b and _landing_names in b][0]
assert f"ssl_certificate     /etc/nginx/certs/{_land}/fullchain.pem;" in _info443 and "location /info/" in _info443 \
    and "alias /srv/www/landing/;" in _info443.split("location /info/")[1], "the page over HTTPS on its names, at /info/ too"
_default80 = [b for b in _blocks if "listen 80 default_server;" in b][0]
assert "location /info/" in _default80 and "alias /srv/www/landing/;" in _default80.split("location /info/")[1] \
    and "return 302 /info/;" in _default80 and "if ($fabric_https_name)" in _default80 \
    and f"return 301 https://{_host_fqdn}$request_uri;" in _default80.split("location /manual/")[1], \
    "http://<host_ip>/info/ and any other name: the page; its manual link to the host's own name over HTTPS"
_map = _ngx.split("map $host $fabric_https_name {")[1].split("}")[0]
assert all(f"        {n} 1;" in _map for n in (v2['hostname_bind9'], v2['hostname_stepca'], v2['hostname_openbao'],
                                                v2['hostname_keycloak'])) and _land not in _map and "default 0;" in _map, \
    _map
assert 'id="root-fp"' in _landing and "/certs/ca-certs.json" in _landing and 'href="/manual/"' in _landing \
    and _land not in _landing, "the page shows the root's fingerprint; its links are relative, so it works anywhere"
_db_apex = env.get_template('bind9/data/zone.j2').render(**full, federation_links={}, zone_name=v2['domain'],
                                                         zone_records=_zone["dynamic_zone_var"])
assert re.search(r"^@\s+A\s+", _db_apex, re.M) and re.search(r"^info\s+CNAME\s+", _db_apex, re.M), \
    "the zone answers for <domain> (it serves the page) and, on a new install, for info"
print("the landing page at /info/ on every name and at its names (info, <domain>, the host's): HTTP without a "
      "redirect, the CA and its fingerprint; nothing depends on info.<domain> (2.1.4.3, 2.1.4.6)")

# the landing page's names follow the zone (2.1.4.8, manual 1.4.2.6): the host's own name, <domain>, and every alias of
# the host the admin keeps; the certificate holds exactly these (setup/mint_service_certs), nginx serves them
from fabriclib.dns.common.landing_names import landing_names  # noqa: E402
_d = v2['domain']
assert landing_names(v2) == [_host_fqdn, _d, f"info.{_d}"], landing_names(v2)
_ren = copy.deepcopy(v2)
_z = _ren["dns"]["dynamic_zone_var"]
_z["CNAME"] = [r for r in _z["CNAME"] if r["name"] != "info"] + [
    {"name": "welcome", "canonical": v2["hostname"]},                         # info renamed
    {"name": "www", "canonical": "welcome"},                                  # a CNAME to the alias: also the host
    {"name": "abs", "canonical": f"{v2['hostname']}.{_d}."},                  # an absolute target
    {"name": "*.apps", "canonical": v2["hostname"]},                          # a wildcard: never a landing name
    {"name": "_acme-challenge", "canonical": v2["hostname"]},                 # not a host name
    {"name": "elsewhere", "canonical": "nas25-apps"}]                         # another machine
_z["A"] = list(_z["A"]) + [{"name": "home", "ip": v2["host_ip"]}, {"name": "nas25-apps", "ip": "192.168.7.20"}]
_names = landing_names(_ren)
assert _names == [_host_fqdn, _d, f"abs.{_d}", f"home.{_d}", f"welcome.{_d}", f"www.{_d}"], _names
# covers: setting:hostname_landing -
assert f"info.{_d}" not in _names and f"elsewhere.{_d}" not in _names and f"calibre.{_d}" not in _names \
    and not any(n.startswith(("ca.", "dns.", "sso.", "vault.", "ntp.", "*", "_")) for n in _names), \
    "only the current aliases of the host: never the old name, another machine, a wildcard or fabric's own names"
_ngx_ren = env.get_template('nginx/nginx.conf.j2').render(**{**full, 'dns': _ren['dns']})
_srv = f"server_name {' '.join(_names)};"
assert _ngx_ren.count(_srv) == 2 and f"ssl_certificate     /etc/nginx/certs/{_land}/fullchain.pem;" in \
    [b for b in re.split(r"\n    server \{", _ngx_ren) if "listen 443 ssl;" in b and _srv in b][0] \
    and not [ln for ln in _ngx_ren.splitlines() if "server_name" in ln and f"info.{_d}" in ln], \
    "nginx serves the renamed alias on HTTP and HTTPS with the landing certificate (its folder keeps its name)"
# a name fabric's other services answer at is never a landing name, even when the admin points one at the host
_clash = copy.deepcopy(v2)
_clash["dns"]["dynamic_zone_var"]["CNAME"].append({"name": "radius", "canonical": v2["hostname"]})
_clash["hostname_radius"] = f"radius.{_d}"
assert f"radius.{_d}" not in landing_names(_clash), landing_names(_clash)
assert landing_names({"hostname": "h", "domain": "d.test"}) == ["h.d.test", "d.test"], "no zone: fabric's names"
print("the landing names follow the zone: a renamed alias, CNAME chains, absolute targets; never the old name, "
      "another machine, a wildcard or fabric's names (2.1.4.8)")

# the CA at /certs/ (1.5.1.5, 2.1.5.11): certs.<domain> is gone everywhere — no server, no DNS name, no certificate;
# ca.<domain> and /certificates send browsers to the page at the host's own name; every leaf names the CRL at
# ca.<domain>, and the page, the scripts and the admin's README name it there, never info.<domain> (1.5.1.6, 2.1.4.6)
_certs_url = f"http://{v2['hostname_stepca']}/certs/"      # the CA's own name, fabric's (1.5.1.6)
assert 'certs.' + v2['domain'] not in _ngx and 'hostname_certs' not in _ngx, "no certs.<domain> server (no redirect)"
assert 'certs' not in [r['name'] for r in v2['dns']['dynamic_zone_var']['CNAME']], "no certs CNAME by default"
assert not re.search(r"^certs\s", _db_apex, re.M), "the zone has no certs record"
_ca = [b for b in _blocks if f"server_name {v2['hostname_stepca']};" in b][0]
assert f"return 302 https://{_host_fqdn}/certs/;" in _ca and f"return 301 https://{_host_fqdn}/certs/;" in _ca, _ca
assert "location /certs/" in _info443 and "return 301 /certs/;" in _info443.split("location /certs/")[0]
assert "location /certs/" in _default80 and "root /srv/www;" in _default80, "http://<host_ip>/certs/ serves the CA"
for _tpl in ('stepca/leaf.tpl.j2', 'stepca/acme.tpl.j2'):
    _t = env.get_template(_tpl).render(**full)
    assert f'"crlDistributionPoints": ["{_certs_url}crl/intermediate.crl"]' in _t and 'certs.' not in _t \
        and _land not in _t, (_tpl, _t)
_page = env.get_template('nginx/www/certs/index.html.j2').render(**{**full, 'domain_file': 'lan'})
assert f"<code>{_certs_url}</code>" in _page and f"{_certs_url}join-linux.sh" in _page and 'certs.' + v2['domain'] \
    not in _page and _land not in _page, "the certificate page names ca.<domain>/certs/"
for _tpl, _var in (('install-all-ubuntu.sh.j2', 'BASE_URL'), ('install-certs.sh.j2', 'CERT_BASE'),
                   ('join-linux.sh.j2', 'CERTS')):
    _t = env.get_template('nginx/www/certs/' + _tpl).render(**{**full, 'domain_file': 'lan'})
    assert f'{_var}="{_certs_url[:-1]}"' in _t and 'certs.' + v2['domain'] not in _t and _land not in _t, \
        (_tpl, _t[:400])
assert 'href="/certs/"' in _landing and 'href="/certs/#join"' in _landing, "landing links"
assert _certs_url in off_txt and 'certs.' + v2['domain'] not in off_txt, "the admin's README names ca.<domain>/certs/"
from fabriclib.pki.acme_info import acme_info  # noqa: E402
assert any(f"{_certs_url} (check its fingerprint" in x for x in acme_info(v2)), acme_info(v2)
print("the CA at /certs/: no certs.<domain> server, name or CNAME; ca.<domain> and /certificates redirect to the "
      "host's own name; leaves name the CRL at ca.<domain>; the page, scripts and README use it (1.5.1.5, 1.5.1.6)")
# Free-text labels (manual 1.1.5.7): whatever they hold, the settings file reads them back exactly, the pages escape
# them, and the client scripts quote them, so nothing in a label is ever run on a client.
import subprocess  # noqa: E402
import tempfile  # noqa: E402
HOSTILE = "Acme: Inc # \"q\" $(touch PWNED) `touch PWNED2` <b>x</b> & it's\nline two"
HOSTILE_SH = HOSTILE.replace("\n", " ")   # one line, so each script line that carries it can run alone
LABELS = ("friendly_name", "service_mark", "care_of", "trademark", "copyright", "contact_email", "contact_phone",
          "address_line1", "address_line2", "ca_name")
_lv = yaml.safe_load(env.get_template('vars.yaml.j2').render(**{**copy.deepcopy(PRISTINE),
                                                                 **{k: HOSTILE for k in LABELS}}))
# covers: setting:friendly_name setting:service_mark setting:care_of setting:trademark setting:copyright +
# covers: setting:contact_email setting:contact_phone setting:address_line1 setting:address_line2 setting:ca_name +
assert all(_lv[k] == HOSTILE for k in LABELS), {k: _lv[k] for k in LABELS if _lv[k] != HOSTILE}
_lpage = env.get_template('nginx/www/shared/base.html.j2').render(**{**full, **{k: HOSTILE for k in LABELS}})
assert "<b>x</b>" not in _lpage and "&lt;b&gt;x&lt;/b&gt;" in _lpage, "a label is escaped in the pages"
with tempfile.TemporaryDirectory() as _d:
    for _name in ("install-certs.sh.j2", "install-chrome-ubuntu.sh.j2", "install-firefox-ubuntu.sh.j2",
                  "install-python-ubuntu.sh.j2"):
        _sh = env.get_template(f'nginx/www/certs/{_name}').render(**{**full, 'friendly_name': HOSTILE_SH})
        assert subprocess.run(["bash", "-n"], input=_sh, text=True).returncode == 0, f"{_name} does not parse"
        for _line in _sh.splitlines():       # run each line that carries the label, alone, where a canary would land
            if "Acme" in _line and ("FRIENDLY_NAME=" in _line or _line.lstrip().startswith(("echo", "if"))):
                _cmd = _line.strip().split(" | ")[0].removesuffix("; then").removeprefix("if ! ")
                if _cmd.startswith("grep"):
                    continue                 # needs the bundle; the quoting is the echo's and assignment's
                _out = subprocess.run(["bash", "-c", _cmd + ('; printf %s "$FRIENDLY_NAME"' if "=" in _cmd.split()[0]
                                                             else "")], cwd=_d, capture_output=True, text=True)
                assert HOSTILE_SH in _out.stdout, (_name, _cmd, _out.stdout, _out.stderr)
    assert not os.path.exists(os.path.join(_d, "PWNED")) and not os.path.exists(os.path.join(_d, "PWNED2")), \
        "nothing in a label ran"
print("free-text labels: read back exactly from vars.yaml, escaped in the pages, quoted in the client scripts "
      "(nothing in one runs, 1.1.5.7)")

# Memory as a budget (manual 1.2.4.3, 2.1.1.47): every installed service's limit is planned from host_ram_capacity;
# the limits add up to the budget, a part turned off leaves more for the others, floors that do not fit are refused.
from fabriclib.deploy.render_vars import render_vars as _render_vars  # noqa: E402
from fabriclib.system.plan_memory import RESERVE_MB  # noqa: E402

PARTS_ON = {'install_kea': True, 'install_freeradius': True, 'install_fluentbit': True, 'dns_filter': 'bind',
            'dhcp': {'interfaces': ['eth0'], 'subnets': [{'subnet': '192.168.7.0/24',
                                                          'pools': ['192.168.7.100 - 192.168.7.199']}]}}
PARTS_OFF = {'install_kea': False, 'install_freeradius': False, 'install_fluentbit': False, 'dns_filter': 'none'}
MEM_KEYS = ('openbao_mem_limit', 'kea_mem_limit', 'samba_mem_limit', 'freeradius_mem_limit', 'fluentbit_mem_limit',
            'resolver_mem_limit', 'adguard_mem_limit')


def mem_vars(**extra):
    """vars.yaml.j2 rendered over the long-running install's settings, then round-tripped once (as apply does)."""
    once = yaml.safe_load(env.get_template('vars.yaml.j2').render(**{**copy.deepcopy(PRISTINE), **extra}))
    return yaml.safe_load(env.get_template('vars.yaml.j2').render(**{**copy.deepcopy(PRISTINE), **once, **extra}))


def compose_limits(v):
    """Each container's limit in MB as the rendered compose files set it, and Keycloak's heap."""
    out = {}
    folders = ['nginx', 'bind9', 'stepca', 'samba', 'keycloak', 'postgres', 'webui', 'openbao'] + \
        [f for f, flag in (('kea', 'install_kea'), ('freeradius', 'install_freeradius'),
                           ('fluentbit', 'install_fluentbit'), ('resolver', 'install_resolver'),
                           ('dnsfilter', 'install_resolver')) if v.get(flag)]
    for folder in folders:
        dc = yaml.safe_load(env.get_template(f'{folder}/docker-compose.yml.j2').render(**{**secrets, **v}))
        for name, spec in dc['services'].items():
            raw = spec.get('mem_limit') or spec['deploy']['resources']['limits']['memory']
            out[name] = int(str(raw).lower().rstrip('m'))
            env_ = spec.get('environment') or {}
            if 'JAVA_OPTS_APPEND' in env_:
                out['keycloak-heap'] = int(re.search(r'-Xmx(\d+)m', env_['JAVA_OPTS_APPEND']).group(1))
    return out


def mem_total(plan):
    return sum(mb * plan['containers'][s] for s, mb in plan['limits'].items()) + plan['unassigned_mb']


CONTAINER_SERVICE = {'nginx': 'nginx', 'bind9': 'bind9', 'step-ca': 'stepca', 'samba': 'samba', 'keycloak': 'keycloak',
                     'postgres': 'postgres', 'webui': 'webui', 'openbao': 'openbao', 'kea-dhcp4': 'kea',
                     'kea-ddns': 'kea', 'freeradius': 'freeradius', 'fluentbit': 'fluentbit',
                     'bind9-resolver': 'resolver', 'adguard-filter': 'adguard'}
mem_plans = {}
for gb in (4, 8):
    for label, parts in (('on', PARTS_ON), ('off', PARTS_OFF)):
        mv = mem_vars(host_ram_capacity=gb, **parts)
        p = mem_plans[(gb, label)] = mv['memory_plan']
        # covers: setting:memory_plan setting:host_ram_capacity +
        assert p['budget_mb'] == gb * 1024 - RESERVE_MB and mem_total(p) == p['budget_mb'], (gb, label, p)
        assert all(mv[k] is None for k in MEM_KEYS), 'no *_mem_limit is written back unless the admin set one'
        got = compose_limits(mv)
        for container, mb in got.items():
            if container != 'keycloak-heap':       # AdGuard Home's container: its share x 2.5 (p['bursts'])
                svc = CONTAINER_SERVICE[container]
                assert mb == (p['bursts'].get(svc) or p['limits'][svc]), (gb, label, container, mb, p['limits'])
        assert got['keycloak-heap'] == int(p['limits']['keycloak'] * 0.8), got
        assert (label == 'on') == ('kea-dhcp4' in got and 'freeradius' in got and 'bind9-resolver' in got
                                   and 'adguard-filter' in got), got
        assert (p['over_mb'] > 0) == (label == 'on'), p    # only AdGuard Home's rebuilds pass the budget, briefly
for gb in (4, 8):
    on, off = mem_plans[(gb, 'on')]['limits'], mem_plans[(gb, 'off')]['limits']
    assert all(off[s] > on[s] for s in ('keycloak', 'samba', 'postgres', 'bind9')), (gb, on, off)
    assert 'kea' not in off and 'resolver' not in off and on['kea'] == 128, (on, off)
assert all(mem_plans[(8, k)]['limits']['keycloak'] > mem_plans[(4, k)]['limits']['keycloak'] for k in ('on', 'off'))
print('memory: the limits add up to the budget and are what the compose files set; a part off leaves more for the '
      'others:\n  ' + '\n  '.join(f"{gb} GB, parts {k}: " + ', '.join(f'{s} {mb}' for s, mb in
                                                                         mem_plans[(gb, k)]['limits'].items())
                                  for gb in (4, 8) for k in ('on', 'off')))

# overrides: memory_floors / memory_weights taken when valid, refused (with the reason) when not
mv = mem_vars(host_ram_capacity=8, memory_floors={'keycloak': 2048, 'postgres': '256m'}, memory_weights={'samba': 0})
p = mv['memory_plan']
# covers: setting:memory_floors setting:memory_weights +
assert p['limits']['keycloak'] > 2048 and p['limits']['samba'] == 512 and p['limits']['postgres'] >= 256 \
    and mem_total(p) == p['budget_mb'], p


def mem_refused(**extra):
    """render_vars' refusal (what apply and setup say) for these settings, or ''."""
    try:
        _render_vars(env, secrets, {**copy.deepcopy(PRISTINE), **extra})
    except ValidationError as e:
        return str(e)
    return ''


for bad, needle in ((dict(memory_floors={'tomcat': 64}), 'no service tomcat'),
                    (dict(memory_floors={'keycloak': 0}), 'a positive number of MB'),
                    (dict(memory_floors={'keycloak': 'lots'}), 'not a memory size'),
                    (dict(memory_floors=['keycloak']), 'a map of service'),
                    (dict(memory_weights={'samba': -1}), 'a number, 0 or more'),
                    (dict(memory_weights={'samba': 'x'}), 'a number, 0 or more'),
                    (dict(memory_weights={'dhcp': 1}), 'no service dhcp')):
    msg = mem_refused(host_ram_capacity=4, **bad)
    # covers: setting:memory_floors setting:memory_weights -
    assert needle in msg and 'did not render' not in msg, (bad, msg)
# floors that do not fit: refused, naming the parts to turn off with what each frees, and the memory needed
msg = mem_refused(host_ram_capacity=4, memory_floors={'keycloak': 2600}, **PARTS_ON)
# covers: setting:memory_plan -
assert 'Turn off DHCP (install_kea: false), 256 MB' in msg and '802.1X (install_freeradius: false), 128 MB' in msg \
    and 'the DNS filter (dns_filter: none), 512 MB' in msg and 'give fabric 6 GB' in msg, msg
print('memory: floors and weights overridden when valid, refused when not; a plan whose floors do not fit is refused, '
      'naming the parts to turn off')

# an explicit *_mem_limit wins (that limit, fixed); its pre-0.9 default counts as not set; a size that is none, refused
mv = mem_vars(host_ram_capacity=4, kea_mem_limit='96m', samba_mem_limit='600m', resolver_mem_limit='384m', **PARTS_ON)
p = mv['memory_plan']
# covers: setting:samba_mem_limit +
assert p['limits']['kea'] == 96 and p['limits']['samba'] == 600 and mv['kea_mem_limit'] == '96m' \
    and mv['samba_mem_limit'] == '600m' and mv['resolver_mem_limit'] is None \
    and p['explicit'] == {'kea': 96, 'samba': 600} and mem_total(p) == p['budget_mb'], p
assert compose_limits(mv)['samba'] == 600 and compose_limits(mv)['kea-ddns'] == 96
# AdGuard Home's adguard_mem_limit is its container's limit, rebuilds included: the budget counts it / 2.5; its 0.7.0
# default (1 GiB at 4 GB) counts as not set (2.1.12.8)
mv = mem_vars(host_ram_capacity=4, adguard_mem_limit='800m', **PARTS_ON)
p = mv['memory_plan']
# covers: setting:adguard_mem_limit +
assert p['explicit'] == {'adguard': 800} and p['limits']['adguard'] == 320 and p['bursts'] == {'adguard': 800}     and compose_limits(mv)['adguard-filter'] == 800 and mem_total(p) == p['budget_mb'], p
mv = mem_vars(host_ram_capacity=4, adguard_mem_limit='1024m', **PARTS_ON)
assert mv['memory_plan']['explicit'] == {} and mv['adguard_mem_limit'] is None, mv['memory_plan']
for key in MEM_KEYS:
    msg = mem_refused(host_ram_capacity=4, **{key: '12x'})
    # covers: setting:openbao_mem_limit setting:kea_mem_limit setting:samba_mem_limit -
    # covers: setting:freeradius_mem_limit setting:fluentbit_mem_limit setting:resolver_mem_limit -
    # covers: setting:adguard_mem_limit -
    assert f"{key}: '12x' is not a memory size" in msg, (key, msg)
print("memory: an explicit *_mem_limit fixes that service's limit (its pre-0.9 default does not), a bad size refused")
