# src/webui/httpio

Reading a request (form, upload, cookie) and building a Set-Cookie header. Not named `http`: server.py runs as a script with src/webui/ first on the import path, where a package `http` would shadow the standard library.

| File | What |
|---|---|
| `cookie_header.py` | Build a Set-Cookie header for the web UI's host-only cookies. |
| `read_cookie.py` | Read one cookie from the request. |
| `read_form.py` | Read and parse a POST body: urlencoded or multipart form data. |
| `upload_value.py` | Take a value from an upload field or, if none was uploaded, from its paste field; binary files (DER) are base64-encoded for the agent. |
| `__init__.py` | Empty; makes it a package |
| `multipart_stream.py` | A multipart body read part by part as it arrives, a part's data in pieces (a bundle's upload) |
