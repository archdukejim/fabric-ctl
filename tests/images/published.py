"""fabric's published images on hosts (manual 1.14.3): which image a host runs, rendered through the real templates.
Run by tests/images/run.sh; no Docker needed.

- the lock as it is: every image published, except those marked pending (with why), which build locally
- a lock with digests: each names its published image and has no build section; the Kea check uses it too
- custom ids for an account: that image is built locally again (2.1.14.5); images without an account are not affected
- the lock's ids equal the Dockerfiles' defaults and vars.yaml.j2's default service accounts
- the rule itself (published_image) and the relaxed-settings list
- the signer the lock trusts: the images workflow under either repository name (2.1.1.68), nothing else
- stale published images (2.1.14.13): the lock as it is passes; a changed source without `pending`, or a published
  image without a source hash, is refused
- the image settings (image_debian, image_stepca, image_keycloak, image_kea, image_freeradius, image_samba,
  image_webui, image_nginx, image_postgres, image_openbao, image_fluentbit, image_cosign): a value set is what the
  rendered compose files build from or run; image_pins holds an image of fabric's at the admin's ref
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.common.read_images_lock import read_images_lock  # noqa: E402
from fabriclib.common.read_published_lock import read_published_lock  # noqa: E402
from fabriclib.dhcp.common.kea_image import kea_image  # noqa: E402
from fabriclib.images.effective_service import effective_service  # noqa: E402
from fabriclib.images.constants import SERVICES  # noqa: E402
from fabriclib.images.published_image import GROUP_ACCOUNTS, published_image  # noqa: E402
from fabriclib.system.relaxed_settings import relaxed_settings  # noqa: E402
sys.path.insert(0, os.path.join(REPO, "scripts", "images"))
import source_hash  # noqa: E402

IMAGES = ["bind9", "freeradius", "kea", "keycloak", "samba", "stepca", "webui"]
PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {detail}")


def render(templates, out, test_vars=None):
    env = dict(os.environ, FABRIC_TEST_TEMPLATES=templates, FABRIC_TEST_VARS=json.dumps(test_vars or {}))
    res = subprocess.run([sys.executable, os.path.join(REPO, "tests", "render.py"), out], env=env,
                         capture_output=True, text=True)
    if res.returncode != 0:
        print(res.stdout[-1500:], res.stderr[-1500:])
    return {name: yaml.safe_load(open(os.path.join(out, name, "docker-compose.yml")))["services"]
            for name in sorted(os.listdir(out)) if os.path.exists(os.path.join(out, name, "docker-compose.yml"))}


def images_of(services):
    return {svc["image"] for svc in services.values()}


def builds(services):
    return any("build" in svc for svc in services.values())


work = tempfile.mkdtemp(prefix="fabric-published-")
try:
    # the lock as it is: every image published, or pending (built locally until its first publish)
    lock = read_published_lock(os.path.join(REPO, "config"))
    unpublished = [n for n in IMAGES if not lock["images"][n]["ref"]]
    plain = render(os.path.join(REPO, "templates"), os.path.join(work, "plain"))
    if unpublished == IMAGES:
        check("without published digests every image builds locally, as before",
              all(builds(plain[n]) and all(i.startswith("fabric/") for i in images_of(plain[n])) for n in IMAGES),
              {n: sorted(images_of(plain[n])) for n in IMAGES})
    else:
        pending = [n for n in IMAGES if lock["images"][n].get("pending")]
        check("the lock pins a published digest for every image not marked pending (none half-published)",
              unpublished == pending, {"unpublished": unpublished, "pending": pending})
        check("a pending image builds locally until it is published",
              all(builds(plain[n]) and all(i.startswith("fabric/") for i in images_of(plain[n])) for n in pending),
              {n: sorted(images_of(plain[n])) for n in pending})

    # a lock with every image published (fake digests: rendering never pulls)
    tree = os.path.join(work, "tree")
    os.makedirs(os.path.join(tree, "config"))
    os.symlink(os.path.join(REPO, "templates"), os.path.join(tree, "templates"))
    text = lock_text_all = open(os.path.join(REPO, "config", "images.lock.yaml")).read()
    for i, name in enumerate(IMAGES):
        digest = "sha256:" + f"{i + 1:x}" * 64
        text = re.sub(rf'^(    {name}: +\{{var: \S+, )tag: "[^"]*", digest: "[^"]*"',
                      rf'\g<1>tag: "9.9.9-rc.1", digest: "{digest}"', text, flags=re.M)
    open(os.path.join(tree, "config", "images.lock.yaml"), "w").write(text)
    published = read_published_lock(os.path.join(tree, "config"))["images"]
    refs = {n: published[n]["ref"] for n in IMAGES}
    check("the test lock pins every image", all(refs.values()), refs)
    pub = render(os.path.join(tree, "templates"), os.path.join(work, "published"))
    for n in IMAGES:
        # covers: setting:image_fabric_bind9 setting:image_fabric_freeradius setting:image_fabric_kea +
        # covers: setting:image_fabric_keycloak setting:image_fabric_samba setting:image_fabric_stepca +
        # covers: setting:image_fabric_webui +
        check(f"{n}: a default host runs the published image ({refs[n].split('@')[0]}) and builds nothing",
              images_of(pub[n]) == {refs[n]} and not builds(pub[n]), sorted(images_of(pub[n])))
    rendered_vars = yaml.safe_load(open(os.path.join(work, "published", "vars.yaml")))
    check("the Kea configuration check uses the published Kea image",
          kea_image(jinja_env(os.path.join(tree, "templates")), rendered_vars) == refs["kea"])
    check("vars.yaml carries image_fabric_* and the cosign pin, the signature check on by default",
          all(rendered_vars[f"image_fabric_{n}"] == refs[n] for n in IMAGES)
          and "@sha256:" in rendered_vars["image_cosign"] and rendered_vars["image_signature_check"] is True)

    # a rolled-back image of fabric's keeps its older ref (image_rolled_back); one not listed follows the lock
    old_bind = refs["bind9"].split("@")[0].rsplit(":", 1)[0] + ":0.6.2-rc.47@sha256:" + "f" * 64
    back = render(os.path.join(tree, "templates"), os.path.join(work, "rolledback"),
                  {"image_rolled_back": ["image_fabric_bind9"], "image_fabric_bind9": old_bind,
                   "image_fabric_kea": old_bind})
    back_vars = yaml.safe_load(open(os.path.join(work, "rolledback", "vars.yaml")))
    # covers: setting:image_rolled_back +
    check("a rolled-back image of fabric's keeps its older ref; another follows the lock (0.6.3 image-update test)",
          old_bind in images_of(back["bind9"]) and back_vars["image_fabric_kea"] == refs["kea"]
          and back_vars["image_rolled_back"] == ["image_fabric_bind9"], (images_of(back["bind9"]), back_vars.get(
              "image_fabric_kea")))

    # image_pins: an image of fabric's the admin set keeps the admin's ref; one not listed follows the lock
    old_kea = refs["kea"].split("@")[0].rsplit(":", 1)[0] + ":0.6.2-rc.47@sha256:" + "e" * 64
    old_webui = refs["webui"].split("@")[0].rsplit(":", 1)[0] + ":0.6.2-rc.47@sha256:" + "d" * 64
    held = render(os.path.join(tree, "templates"), os.path.join(work, "pinned"),
                  {"image_pins": ["image_fabric_kea"], "image_fabric_kea": old_kea, "image_fabric_webui": old_webui})
    held_vars = yaml.safe_load(open(os.path.join(work, "pinned", "vars.yaml")))
    # covers: setting:image_pins +
    check("image_pins: the admin's Kea image is what the host runs; the web UI (not pinned) follows the lock",
          images_of(held["kea"]) == {old_kea} and images_of(held["webui"]) == {refs["webui"]}
          and held_vars["image_pins"] == ["image_fabric_kea"], (images_of(held["kea"]), images_of(held["webui"])))

    # custom ids for the DNS account: bind9 is built locally (its ids are baked in); stepca (no account) is not
    users = {"bind": {"uid": 700, "gid": 700, "name": "fabric-dns"}}
    custom = render(os.path.join(tree, "templates"), os.path.join(work, "custom"), {"service_users": users})
    check("custom ids for the bind account: bind9 builds locally again (2.1.14.5)",
          builds(custom["bind9"]) and images_of(custom["bind9"]) == {"fabric/bind9:local"}
          and custom["bind9"]["bind9"]["build"]["args"]["BIND_UID"] == "700")
    check("custom bind ids leave the images without that account published",
          images_of(custom["stepca"]) == {refs["stepca"]} and images_of(custom["kea"]) == {refs["kea"]})

    # the image settings: a host that builds locally (no published digests) takes each value set as it is
    local = os.path.join(work, "local")
    os.makedirs(os.path.join(local, "config"))
    os.symlink(os.path.join(REPO, "templates"), os.path.join(local, "templates"))
    open(os.path.join(local, "config", "images.lock.yaml"), "w").write(     # the published digests blanked
        re.sub(r'(tag: )"[^"]*", (digest: )"[^"]*"', r'\1"", \2""', lock_text_all))
    mine = {var: f"registry.test/fabric-test/{var[6:]}:1@sha256:{c * 64}" for var, c in
            zip(["image_debian", "image_stepca", "image_keycloak", "image_nginx", "image_postgres", "image_openbao",
                 "image_fluentbit", "image_cosign"], "abcdef12")}
    mine.update({var: f"fabric-test/{var[6:]}:custom" for var in
                 ["image_kea", "image_freeradius", "image_samba", "image_webui"]})
    # tests/render.py holds every image to the lock's refs, so the host is rendered there with the defaults, then its
    # vars.yaml with these values set goes through vars.yaml.j2 and the compose templates again, the way deploy does
    render(os.path.join(local, "templates"), os.path.join(work, "local-default"))
    local_env = jinja_env(os.path.join(local, "templates"))
    own_vars = yaml.safe_load(local_env.get_template("vars.yaml.j2").render(
        **{**yaml.safe_load(open(os.path.join(work, "local-default", "vars.yaml"))), **mine}))
    own = {n: yaml.safe_load(local_env.get_template(f"{n}/docker-compose.yml.j2").render(**own_vars))["services"]
           for n in [*IMAGES, "nginx", "postgres", "openbao", "fluentbit"]}
    base_of = {"bind9": "image_debian", "freeradius": "image_debian", "kea": "image_debian", "samba": "image_debian",
               "webui": "image_debian", "stepca": "image_stepca", "keycloak": "image_keycloak"}

    def bases(name):
        return {s["build"]["args"]["BASE_IMAGE"] for s in own[name].values() if "build" in s}

    # covers: setting:image_debian setting:image_stepca setting:image_keycloak +
    check("image_debian, image_stepca, image_keycloak: each local build's base is the value set",
          all(bases(n) == {mine[v]} for n, v in base_of.items()), {n: bases(n) for n in base_of})
    named = {"kea": "image_kea", "freeradius": "image_freeradius", "samba": "image_samba", "webui": "image_webui"}
    # covers: setting:image_kea setting:image_freeradius setting:image_samba setting:image_webui +
    check("image_kea, image_freeradius, image_samba, image_webui: the local build's image name is the value set",
          all(images_of(own[n]) == {mine[v]} for n, v in named.items()), {n: images_of(own[n]) for n in named})
    pulled = {"nginx": "image_nginx", "postgres": "image_postgres", "openbao": "image_openbao",
              "fluentbit": "image_fluentbit"}
    # covers: setting:image_nginx setting:image_postgres setting:image_openbao setting:image_fluentbit +
    check("image_nginx, image_postgres, image_openbao, image_fluentbit: the image pulled is the value set, not built",
          all(images_of(own[n]) == {mine[v]} and not builds(own[n]) for n, v in pulled.items()),
          {n: images_of(own[n]) for n in pulled})
    lock_refs = {e["var"]: e["ref"] for e in read_images_lock(os.path.join(REPO, "config")).values()}
    check("without them each takes the lock's validated ref (nginx, postgres, openbao, fluentbit, cosign)",
          all(images_of(plain[n]) == {lock_refs[v]} for n, v in pulled.items())
          and yaml.safe_load(open(os.path.join(work, "plain", "vars.yaml")))["image_cosign"] == lock_refs["image_cosign"])
    # covers: setting:image_cosign +
    check("image_cosign: vars.yaml carries the value set (the cosign the signature check runs, verify.py)",
          own_vars["image_cosign"] == mine["image_cosign"], own_vars.get("image_cosign"))

    # the lock's ids are what the Dockerfiles bake in and what vars.yaml.j2 gives by default
    defaults = yaml.safe_load(open(os.path.join(work, "plain", "vars.yaml")))["service_users"]
    wrong = []
    for n in IMAGES:
        e = published[n]
        dockerfile = open(os.path.join(REPO, "packaging", "images", n, "Dockerfile")).read()
        args = dict(re.findall(r"^ARG (\w+_[UG]ID)=(\d+)$", dockerfile, re.M))
        uid = next((k for k in args if k.endswith("_UID")), None)
        baked = f"{args[uid]}:{args.get(uid[:-4] + '_GID', '')}" if uid else ""
        if (e.get("ids") or "") != baked:
            wrong.append(f"{n}: lock {e.get('ids')!r}, Dockerfile {baked!r}")
        # other services' groups (a *_GID without its *_UID): the lock's `groups`, the vars' default gids
        groups = ",".join(f"{k}={args[k]}" for k in sorted(args) if k.endswith("_GID") and k[:-4] + "_UID" not in args)
        if (e.get("groups") or "") != groups:
            wrong.append(f"{n}: lock groups {e.get('groups')!r}, Dockerfile {groups!r}")
        for pair in filter(None, groups.split(",")):
            key, gid = pair.split("=")
            if str(defaults[GROUP_ACCOUNTS[key]]["gid"]) != gid:
                wrong.append(f"{n}: {key} {gid}, vars default {defaults[GROUP_ACCOUNTS[key]]['gid']}")
        if e.get("account"):
            u = defaults[e["account"]]
            if f"{u['uid']}:{u['gid']}" != e["ids"]:
                wrong.append(f"{n}: vars default {u['uid']}:{u['gid']}")
    check("the lock's ids match the Dockerfiles and the default service accounts", not wrong, wrong)

    # the rule and what fabricctl images makes of it
    e = published["bind9"]
    host = {"image_fabric_bind9": refs["bind9"], "service_users": {"bind": {"uid": 600, "gid": 600}}}
    check("published_image: in use for a default host", published_image(host, e) == refs["bind9"])
    check("published_image: refused when not pinned by digest",
          published_image(dict(host, image_fabric_bind9="ghcr.io/x/bind9:1.0"), e) == "")
    check("published_image: refused for other ids or an unset var",
          published_image(dict(host, service_users={"bind": {"uid": 600, "gid": 601}}), e) == ""
          and published_image({"service_users": host["service_users"]}, e) == "")
    dc_entry = published["samba"]
    dc = {"image_fabric_samba": refs["samba"],
          "service_users": {"bind": {"uid": 600, "gid": 600}, "freeradius": {"uid": 610, "gid": 610}}}
    check("published_image: the DC's image in use when BIND's and FreeRADIUS's gids are the baked ones",
          published_image(dc, dc_entry) == refs["samba"])
    check("published_image: the DC builds locally when a baked group's gid differs (2.1.14.5)",
          published_image(dict(dc, service_users={**dc["service_users"], "bind": {"uid": 600, "gid": 700}}),
                          dc_entry) == "")
    svc = next(s for s in SERVICES if s["name"] == "bind9")
    eff = effective_service(svc, host, published)
    check("fabricctl images sees bind9 on its published image (own var, no local build)",
          eff["var"] == "image_fabric_bind9" and eff["build"] is None and svc["build"] == "fabric/bind9:local")
    check("relaxed settings: none by default, the signature opt-out listed when set",
          relaxed_settings({}) == [] and relaxed_settings({"image_signature_check": False})[0]["setting"]
          == "image_signature_check: false")

    # stale published images (2.1.14.13): the real hashes once, then locks that differ only in the published section
    now = source_hash.source_hashes(REPO)
    check("source hashes: one per fabric image",
          sorted(now) == IMAGES and all(v.startswith("sha256:") for v in now.values()), now)
    problems = source_hash.check(REPO)
    check("the lock as it is: every published image matches its sources or is marked pending", not problems, problems)

    # the signer the lock trusts: the images workflow under either of the repository's names (2.1.1.68)
    signer = re.compile(read_published_lock(os.path.join(REPO, "config"))["signer"])
    wf = "https://github.com/archdukejim/{}/.github/workflows/images.yml@refs/{}"
    good = [wf.format(name, ref) for name in ("open-fabric", "fabric-ctl")
            for ref in ("heads/main", "heads/rc/0.8.0", "tags/v0.8.0-rc.1")]
    check("the signer: the images workflow of open-fabric (the images published before the rename) and of fabric-ctl, "
          "from main, an rc/ branch or a v tag", all(signer.search(i) for i in good),
          [i for i in good if not signer.search(i)])
    bad = [wf.format("someone-else", "heads/main"), wf.format("fabric-ctl", "heads/dev/0.8.0"),
           "https://github.com/archdukejim/fabric-ctl/.github/workflows/other.yml@refs/heads/main",
           "https://github.com/archdukejim/fabric-ctl-fork/.github/workflows/images.yml@refs/heads/main",
           "https://github.com/evil/archdukejim/fabric-ctl/.github/workflows/images.yml@refs/heads/main"]
    check("negative: the signer refuses another repository, a dev/ branch, another workflow and a look-alike name",
          not any(signer.search(i) for i in bad), [i for i in bad if signer.search(i)])
    real = source_hash.source_hashes
    source_hash.source_hashes = lambda repo=REPO: now
    try:
        lock_text = open(os.path.join(REPO, "config", "images.lock.yaml")).read()

        def check_lock(edit):
            fake = os.path.join(work, "stale")
            os.makedirs(os.path.join(fake, "config"), exist_ok=True)
            with open(os.path.join(fake, "config", "images.lock.yaml"), "w") as f:
                f.write(edit(lock_text))
            return source_hash.check(fake)

        def published_line(name, text, fields):     # every image published (a fake digest), with these fields
            return re.sub(rf'^(    {name}: +\{{var: \S+, )tag: "[^"]*", digest: "[^"]*"[^}}]*',
                          rf'\g<1>tag: "9.9.9-rc.1", digest: "sha256:{"1" * 64}"{fields}', text, flags=re.M)

        def fresh(text):
            for n in IMAGES:
                text = published_line(n, text, f', source: "{now[n]}"')
            return text

        check("a lock whose every source hash matches passes", check_lock(fresh) == [])
        stale = check_lock(lambda t: published_line("bind9", fresh(t), ', source: "sha256:old"'))
        check("refused: bind9's sources changed and it is not marked pending",
              len(stale) == 1 and stale[0].startswith("bind9: its sources changed"), stale)
        check("a changed image marked pending passes", check_lock(lambda t: published_line(
            "bind9", fresh(t), ', source: "sha256:old", pending: "rebuilt with the next candidate"')) == [])
        missing = check_lock(lambda t: published_line("kea", fresh(t), ""))
        check("refused: a published image without a source hash",
              len(missing) == 1 and missing[0].startswith("kea: the lock records no source hash"), missing)
    finally:
        source_hash.source_hashes = real
finally:
    shutil.rmtree(work, ignore_errors=True)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
