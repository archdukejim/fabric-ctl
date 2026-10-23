def registry_name(repo):
    """Purpose: where an image repository lives, as Docker names it (docker.io's short names expanded).
    Inputs:  repo — str, a repository as the lock writes it ("nginx", "keycloak/keycloak",
             "ghcr.io/archdukejim/open-fabric/bind9").
    Returns: (host, path, canonical): the registry's API host ("registry-1.docker.io" for docker.io), the
             repository's path on it ("library/nginx") and the full name Docker gives the image
             ("docker.io/library/nginx").
    Fails:   never — any string is split by Docker's rule (a first part with "." or ":", or "localhost", is a host).
    Feeds:   fetch_blob, fetch_image."""
    first, _, rest = repo.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        host, path = first, rest
    else:
        host, path = "docker.io", repo
    if host == "docker.io" and "/" not in path:
        path = f"library/{path}"
    api = "registry-1.docker.io" if host == "docker.io" else host
    return api, path, f"{host}/{path}"
