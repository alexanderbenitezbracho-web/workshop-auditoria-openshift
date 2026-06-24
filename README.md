# Auditoría de la Consola de Administración y Recursos

Guía práctica para **auditar accesos y operaciones sobre recursos** en OpenShift Container Platform: inicio de sesión en la consola web, consultas (lectura), creación, modificación y eliminación de objetos, filtrando por usuario.

Documentación de referencia:

- [Viewing audit logs (OCP 4.20)](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/security_and_compliance/audit-log-view)
- [Configuring the audit log policy (OCP 4.20)](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/security_and_compliance/audit-log-policy-config)
- [API audit log event structure (Kubernetes)](https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/)

---

## 1. Objetivo

Con esta guía podrás:

1. Entender **dónde** se registran los eventos de auditoría en OpenShift.
2. Consultar logs de los cuatro componentes que auditan peticiones API.
3. **Filtrar por usuario** (por ejemplo `user21`) y por tipo de operación.
4. Distinguir acciones desde la **consola web** frente a la **CLI** (`oc`).
5. Identificar intentos **permitidos** y **denegados** (código HTTP 403).
6. Determinar **quién creó o eliminó un proyecto**.

---

## 2. Conceptos clave

### 2.1. La auditoría ocurre en el API server

OpenShift registra **cada petición HTTP** que llega a los servidores API. Tanto la **consola de administración** como `oc`, operadores, pipelines y aplicaciones generan las mismas entradas de auditoría cuando invocan la API.

No existe un log de auditoría separado “solo para la consola”: la consola es un cliente más de la API.

### 2.2. Cuatro fuentes de logs de auditoría


| Componente                     | Ruta en el nodo (`oc adm node-logs`) | Qué audita                                                                     |
| ------------------------------ | ------------------------------------ | ------------------------------------------------------------------------------ |
| **Kubernetes API server**      | `kube-apiserver/audit.log`           | Pods, Deployments, ConfigMaps, Secrets (metadatos), **Namespaces**, RBAC, etc. |
| **OpenShift API server**       | `openshift-apiserver/audit.log`      | **Projects**, Routes, ImageStreams, BuildConfigs, DeploymentConfigs, etc.      |
| **OpenShift OAuth API server** | `oauth-apiserver/audit.log`          | Users, Groups, OAuthClients                                                    |
| **OpenShift OAuth server**     | `oauth-server/audit.log`             | **Inicio de sesión**, autorización OAuth (`/login`, `/oauth/authorize`)        |


### 2.3. Campos relevantes de cada evento

Cada línea del log es un JSON con campos como:


| Campo                                                 | Descripción                                                                         |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `user.username`                                       | Usuario autenticado que realizó la petición                                         |
| `verb`                                                | Operación Kubernetes: `create`, `get`, `list`, `watch`, `update`, `patch`, `delete` |
| `requestURI`                                          | Endpoint invocado                                                                   |
| `objectRef`                                           | Recurso afectado (`resource`, `namespace`, `name`)                                  |
| `responseStatus.code`                                 | Código HTTP (200, 201, 403, etc.)                                                   |
| `userAgent`                                           | Cliente: `oc/4.x`, navegador (`Mozilla/...`), `curl`, operadores, etc.              |
| `sourceIPs`                                           | IP de origen de la petición                                                         |
| `annotations["authorization.k8s.io/decision"]`        | `allow` o `deny`                                                                    |
| `impersonatedUser.username`                            | Usuario impersonado, si aplica (común en limpieza automática de namespaces)          |
| `annotations["authorization.k8s.io/reason"]`          | Motivo RBAC de la decisión                                                          |
| `annotations["authentication.openshift.io/username"]` | Usuario en eventos del **oauth-server** (login)                                     |
| `annotations["authentication.openshift.io/decision"]` | `allow`, `deny` o `error` en login                                                  |


### 2.4. Perfil de auditoría del clúster

El volumen de detalle lo define `spec.audit.profile` del recurso `APIServer`:

```bash
oc get apiserver cluster -o jsonpath='{.spec.audit.profile}{"\n"}'
```

OpenShift usa por defecto el perfil **Default**. La definición completa de cada perfil está en la [sección 12](#12-perfiles-de-auditoría).

> **Proyectos y namespaces:** operaciones como `oc new-project` y `oc delete project` generan eventos en **dos fases** (usuario + componente del sistema). Para atribuir la acción a una persona, no basta con filtrar `projects` o `namespaces` sin contexto; ver [sección 10](#10-creación-y-eliminación-de-proyectos).

---

## 3. Requisitos


| Requisito                           | Motivo                                                                                |
| ----------------------------------- | ------------------------------------------------------------------------------------- |
| Usuario con rol `**cluster-admin**` | Solo los administradores pueden ejecutar `oc adm node-logs` sobre nodos control plane |
| Cliente `**oc**` autenticado        | Acceso al clúster                                                                     |
| `**jq**` instalado                  | Filtrar y formatear JSON de auditoría                                                 |


```bash
oc login -u admin
oc whoami
# Debe mostrar: admin

which jq
```

> `oc login -u admin` utiliza el clúster del contexto actual en `~/.kube/config`.

---

## 4. Identificar nodos control plane

```bash
oc get nodes -l node-role.kubernetes.io/master= -o name
# En OCP 4.16+ también puede usarse:
# oc get nodes -l node-role.kubernetes.io/control-plane= -o name
```

**Ejemplo en este clúster:**

```
node/ip-10-0-107-138.us-east-2.compute.internal
node/ip-10-0-109-201.us-east-2.compute.internal
node/ip-10-0-95-192.us-east-2.compute.internal
```

> Las peticiones API se reparten entre los nodos control plane. Si no encuentras un evento en un nodo, **repite la búsqueda en los demás**.

```bash
export MASTER_NODE=ip-10-0-107-138.us-east-2.compute.internal
```

---

## 5. Listar y ver logs de auditoría

### 5.1. Listar archivos disponibles

```bash
oc adm node-logs --role=master --path=kube-apiserver/
oc adm node-logs --role=master --path=openshift-apiserver/
oc adm node-logs --role=master --path=oauth-apiserver/
oc adm node-logs --role=master --path=oauth-server/
```

Cada nodo expone `audit.log` (activo) y archivos rotados `audit-YYYY-MM-DDTHH-MM-SS.log`.

### 5.2. Ver el log activo de un nodo

```bash
oc adm node-logs $MASTER_NODE --path=kube-apiserver/audit.log | head -5
```

### 5.3. Ver un archivo rotado

```bash
oc adm node-logs $MASTER_NODE \
  --path=kube-apiserver/audit-2026-06-23T22-59-12.474.log | head -5
```

---

## 6. Filtrar auditoría por usuario

Sustituye `USUARIO_AUDITAR` por el nombre del usuario OpenShift (por ejemplo `user21`).

### 6.1. Todas las operaciones de un usuario (Kubernetes API)

```bash
export USUARIO_AUDITAR=user21

oc adm node-logs $MASTER_NODE \
  --path=kube-apiserver/audit.log \
  | jq -c --arg u "$USUARIO_AUDITAR" 'select(.user.username == $u)'
```

Salida resumida (verbo, recurso, namespace, código):

```bash
oc adm node-logs $MASTER_NODE \
  --path=kube-apiserver/audit.log \
  | jq -r --arg u "$USUARIO_AUDITAR" '
      select(.user.username == $u)
      | "\(.requestReceivedTimestamp) \(.verb) \(.objectRef.resource // "-") \(.objectRef.namespace // "-") \(.objectRef.name // "-") \(.responseStatus.code)"
    '
```

### 6.2. Usuario en OpenShift API server (Projects, Routes, etc.)

```bash
oc adm node-logs $MASTER_NODE \
  --path=openshift-apiserver/audit.log \
  | jq -c --arg u "$USUARIO_AUDITAR" 'select(.user.username == $u)'
```

Para **proyectos**, el recurso depende de la operación:

| Operación | Recurso a filtrar | API server recomendado |
|-----------|-------------------|------------------------|
| `oc new-project` (quién lo pidió) | `projectrequests` | `openshift-apiserver` o `kube-apiserver` |
| `oc delete project` (quién lo eliminó) | `projects` | `kube-apiserver` o `openshift-apiserver` |

```bash
# Proyectos eliminados por el usuario
oc adm node-logs $MASTER_NODE --path=openshift-apiserver/audit.log \
  | jq -c --arg u "$USUARIO_AUDITAR" '
      select(.user.username == $u and .verb == "delete" and .objectRef.resource == "projects")
    '

# Proyectos creados por el usuario (solicitud)
oc adm node-logs $MASTER_NODE --path=openshift-apiserver/audit.log \
  | jq -c --arg u "$USUARIO_AUDITAR" '
      select(.user.username == $u and .verb == "create" and .objectRef.resource == "projectrequests")
    '
```

### 6.3. Inicios de sesión y acceso a la consola (OAuth server)

```bash
oc adm node-logs $MASTER_NODE \
  --path=oauth-server/audit.log \
  | jq -c --arg u "$USUARIO_AUDITAR" '
      select(.annotations["authentication.openshift.io/username"] == $u)
    '
```

Solo accesos a la consola web (`client_id=console`):

```bash
oc adm node-logs $MASTER_NODE \
  --path=oauth-server/audit.log \
  | jq -c --arg u "$USUARIO_AUDITAR" '
      select(
        .annotations["authentication.openshift.io/username"] == $u
        and (.requestURI | contains("client_id=console"))
      )
      | {
          timestamp: .requestReceivedTimestamp,
          uri: .requestURI,
          decision: .annotations["authentication.openshift.io/decision"]
        }
    '
```

### 6.4. Buscar en todos los nodos control plane

```bash
for NODE in $(oc get nodes -l node-role.kubernetes.io/master= -o jsonpath='{.items[*].metadata.name}'); do
  echo "########## $NODE ##########"
  oc adm node-logs "$NODE" --path=kube-apiserver/audit.log 2>/dev/null \
    | jq -c --arg u "$USUARIO_AUDITAR" 'select(.user.username == $u)' \
    | tail -5
done
```

---

## 7. Filtrar por tipo de operación

### 7.1. Creación de recursos (`create`)

```bash
oc adm node-logs $MASTER_NODE --path=kube-apiserver/audit.log \
  | jq -c --arg u "$USUARIO_AUDITAR" '
      select(.user.username == $u and .verb == "create")
    '
```

Para **proyectos nuevos** (`oc new-project`), el usuario aparece en `projectrequests`, no en `projects` (ese `create` lo hace `openshift-apiserver-sa`). Ver [sección 10.1](#101-creación-de-proyectos-oc-new-project).

### 7.2. Lectura / consulta (`get`, `list`, `watch`)

```bash
oc adm node-logs $MASTER_NODE --path=kube-apiserver/audit.log \
  | jq -c --arg u "$USUARIO_AUDITAR" '
      select(.user.username == $u and .verb == "get")
    '

oc adm node-logs $MASTER_NODE --path=kube-apiserver/audit.log \
  | jq -c --arg u "$USUARIO_AUDITAR" '
      select(.user.username == $u and .verb == "list")
    '
```

### 7.3. Modificación (`patch`, `update`)

```bash
oc adm node-logs $MASTER_NODE --path=kube-apiserver/audit.log \
  | jq -c --arg u "$USUARIO_AUDITAR" '
      select(.user.username == $u and (.verb == "patch" or .verb == "update"))
    '
```

### 7.4. Eliminación (`delete`)

```bash
oc adm node-logs $MASTER_NODE --path=kube-apiserver/audit.log \
  | jq -c --arg u "$USUARIO_AUDITAR" '
      select(.user.username == $u and .verb == "delete")
    '
```

Para **proyectos** (`oc delete project`), filtra el recurso `projects`, no `namespaces`. Ver [sección 10.2](#102-eliminación-de-proyectos-oc-delete-project).

### 7.5. Combinar usuario + verbo + recurso

```bash
oc adm node-logs $MASTER_NODE --path=kube-apiserver/audit.log \
  | jq -c --arg u "$USUARIO_AUDITAR" '
      select(
        .user.username == $u
        and .verb == "create"
        and .objectRef.resource == "configmaps"
        and .objectRef.namespace == "terminal-user21"
      )
    '
```

### 7.6. Accesos denegados (403)

```bash
oc adm node-logs $MASTER_NODE --path=kube-apiserver/audit.log \
  | jq -c --arg u "$USUARIO_AUDITAR" '
      select(.user.username == $u and .responseStatus.code == 403)
      | {
          verb: .verb,
          requestURI: .requestURI,
          code: .responseStatus.code,
          decision: .annotations["authorization.k8s.io/decision"]
        }
    '
```

---

## 8. Distinguir consola web frente a CLI

La consola web envía peticiones con `userAgent` de navegador. La CLI usa `oc/x.y`:

```bash
# Acciones desde navegador (consola)
oc adm node-logs $MASTER_NODE --path=kube-apiserver/audit.log \
  | jq -c --arg u "$USUARIO_AUDITAR" '
      select(
        .user.username == $u
        and (.userAgent | test("Mozilla|Chrome|Safari|Firefox"))
      )
      | {verb, requestURI, userAgent, code: .responseStatus.code}
    '

# Acciones desde oc
oc adm node-logs $MASTER_NODE --path=kube-apiserver/audit.log \
  | jq -c --arg u "$USUARIO_AUDITAR" '
      select(.user.username == $u and (.userAgent | startswith("oc/")))
      | {verb, requestURI, userAgent, code: .responseStatus.code}
    '
```

---

## 9. Ejemplo práctico: usuario `user21`

### 9.1. Contexto del usuario


| Atributo                 | Valor                                               |
| ------------------------ | --------------------------------------------------- |
| Usuario                  | `user21`                                            |
| Identity provider        | `workshop`                                          |
| Permisos de clúster      | **No** tiene `cluster-admin`                        |
| Proyecto de terminal web | `terminal-user21`                                   |
| Rol en el proyecto       | `admin` (RoleBinding `admin` → ClusterRole `admin`) |
| Puede crear namespaces   | **No**                                              |


```bash
oc login -u user21 -p workshop
oc auth can-i create configmaps -n terminal-user21    # yes
oc auth can-i create namespaces --all-namespaces      # no
```

### 9.2. Generar eventos de prueba

```bash
oc project terminal-user21

oc create configmap audit-test --from-literal=purpose=auditoria -n terminal-user21
oc patch configmap audit-test -n terminal-user21 -p '{"data":{"updated":"true"}}'
oc get configmap audit-test -n terminal-user21
oc delete configmap audit-test -n terminal-user21
```

Consultar logs como administrador:

```bash
oc login -u admin
oc whoami   # admin
```

### 9.3. Eventos capturados (perfil Default)

**Creación** (`verb: create`, código 201):

```json
{
  "verb": "create",
  "user": {"username": "user21"},
  "objectRef": {
    "resource": "configmaps",
    "namespace": "terminal-user21",
    "name": "audit-test"
  },
  "responseStatus": {"code": 201},
  "userAgent": "oc/4.17.0 (linux/amd64) kubernetes/f4525b8",
  "annotations": {
    "authorization.k8s.io/decision": "allow",
    "authorization.k8s.io/reason": "RBAC: allowed by RoleBinding \"admin/terminal-user21\" of ClusterRole \"admin\" to User \"user21\""
  }
}
```

---

## 10. Creación y eliminación de proyectos

Las operaciones sobre proyectos en OpenShift registran **dos eventos**: uno del **usuario** y otro de un **componente del sistema** (`openshift-apiserver-sa`). Si el filtro no distingue el recurso correcto, verás la ServiceAccount en lugar de la persona.

### 10.1. Creación de proyectos (`oc new-project`)

| Orden | Quién | Recurso | Qué representa |
|-------|-------|---------|----------------|
| 1 | **Usuario humano** | `projectrequests` | Quién solicitó el proyecto |
| 2 | `openshift-apiserver-sa` | `projects` | Creación interna del objeto Project |

Buscar quién creó un proyecto:

```bash
export NOMBRE_PROYECTO=aplicacion-nucleo-datasystems
export USUARIO_AUDITAR=user3

for NODE in $(oc get nodes -l node-role.kubernetes.io/master= -o jsonpath='{.items[*].metadata.name}'); do
  oc adm node-logs "$NODE" --path=openshift-apiserver/audit.log 2>/dev/null \
    | jq -r --arg u "$USUARIO_AUDITAR" '
        select(
          .user.username == $u
          and .verb == "create"
          and .objectRef.resource == "projectrequests"
        )
        | "\(.requestReceivedTimestamp) usuario=\(.user.username) solicitud=\(.objectRef.name) agent=\(.userAgent) code=\(.responseStatus.code)"
      '
done
```

El nombre en `projectrequests` coincide con el del proyecto creado (`aplicacion-nucleo-datasystems` en el ejemplo de `user3`).

### 10.2. Eliminación de proyectos (`oc delete project`)

| Orden | Quién | Recurso | Qué representa |
|-------|-------|---------|----------------|
| 1 | **Usuario humano** | `projects` | Quién ejecutó la eliminación |
| 2 | `openshift-apiserver-sa` | `namespaces` | Limpieza interna del namespace |

Si el filtro solo busca `objectRef.resource == "namespaces"`, obtendrás la **ServiceAccount de OpenShift**, no quien ejecutó el comando.

```
usuario (oc delete project)
    └── delete projects/aplicacion-nucleo-datasystems   ← buscar este evento
            └── openshift-apiserver-sa
                    └── delete namespaces/aplicacion-nucleo-datasystems   ← NO es el usuario
```

#### Dónde buscar

| Acción | API server | Recurso en el log | Usuario en el log |
|--------|------------|-------------------|-------------------|
| `oc delete project <nombre>` | `kube-apiserver` o `openshift-apiserver` | **`projects`** | Usuario que ejecutó el comando |
| Limpieza del namespace (automática) | `kube-apiserver` | `namespaces` | `openshift-apiserver-sa` |
| `oc delete namespace <nombre>` | `kube-apiserver` | `namespaces` | Usuario que ejecutó el comando |
| Eliminación por GitOps / operador | `kube-apiserver` o `openshift-apiserver` | `projects` o `namespaces` | Service account del componente |

#### Comando recomendado

```bash
export NOMBRE_PROYECTO=aplicacion-nucleo-datasystems

for NODE in $(oc get nodes -l node-role.kubernetes.io/master= -o jsonpath='{.items[*].metadata.name}'); do
  echo "########## $NODE ##########"
  oc adm node-logs "$NODE" --path=kube-apiserver/audit.log 2>/dev/null \
    | jq -r --arg p "$NOMBRE_PROYECTO" '
        select(
          .verb == "delete"
          and .objectRef.name == $p
          and (
            .objectRef.resource == "projects"
            or (
              .objectRef.resource == "namespaces"
              and (.user.username | startswith("system:") | not)
            )
          )
        )
        | "\(.requestReceivedTimestamp) usuario=\(.user.username) recurso=\(.objectRef.resource) ip=\(.sourceIPs[0]) agent=\(.userAgent) code=\(.responseStatus.code)"
      '
done
```

Variante directa (solo `projects`):

```bash
for NODE in $(oc get nodes -l node-role.kubernetes.io/master= -o jsonpath='{.items[*].metadata.name}'); do
  oc adm node-logs "$NODE" --path=kube-apiserver/audit.log 2>/dev/null \
    | jq -c --arg p "$NOMBRE_PROYECTO" '
        select(
          .verb == "delete"
          and .objectRef.resource == "projects"
          and .objectRef.name == $p
        )
      '
done
```

También puedes consultar `openshift-apiserver/audit.log` con el mismo filtro sobre `projects`.

#### Ejemplo real: `aplicacion-nucleo-datasystems` eliminado por `user3`

**Evento del usuario** (`oc delete project`):

```json
{
  "verb": "delete",
  "user": {"username": "user3"},
  "requestURI": "/apis/project.openshift.io/v1/projects/aplicacion-nucleo-datasystems",
  "objectRef": {
    "resource": "projects",
    "name": "aplicacion-nucleo-datasystems"
  },
  "responseStatus": {"code": 200},
  "userAgent": "oc/4.17.0 (linux/amd64) kubernetes/f4525b8",
  "requestReceivedTimestamp": "2026-06-24T02:07:51.026565Z",
  "annotations": {
    "authorization.k8s.io/decision": "allow",
    "authorization.k8s.io/reason": "RBAC: allowed by RoleBinding \"admin/aplicacion-nucleo-datasystems\" of ClusterRole \"admin\" to User \"user3\""
  }
}
```

**Evento posterior del sistema** (no confundir con el usuario):

```json
{
  "verb": "delete",
  "user": {"username": "system:serviceaccount:openshift-apiserver:openshift-apiserver-sa"},
  "requestURI": "/api/v1/namespaces/aplicacion-nucleo-datasystems",
  "objectRef": {
    "resource": "namespaces",
    "name": "aplicacion-nucleo-datasystems"
  },
  "userAgent": "openshift-apiserver/v0.0.0 (linux/amd64) kubernetes/$Format"
}
```

### 10.3. Listar proyectos creados o eliminados por un usuario

```bash
export USUARIO_AUDITAR=user3

# Proyectos eliminados
for NODE in $(oc get nodes -l node-role.kubernetes.io/master= -o jsonpath='{.items[*].metadata.name}'); do
  oc adm node-logs "$NODE" --path=kube-apiserver/audit.log 2>/dev/null \
    | jq -r --arg u "$USUARIO_AUDITAR" '
        select(
          .user.username == $u
          and .verb == "delete"
          and .objectRef.resource == "projects"
        )
        | "\(.requestReceivedTimestamp) eliminó proyecto=\(.objectRef.name) code=\(.responseStatus.code)"
      '
done

# Proyectos creados (solicitudes)
for NODE in $(oc get nodes -l node-role.kubernetes.io/master= -o jsonpath='{.items[*].metadata.name}'); do
  oc adm node-logs "$NODE" --path=openshift-apiserver/audit.log 2>/dev/null \
    | jq -r --arg u "$USUARIO_AUDITAR" '
        select(
          .user.username == $u
          and .verb == "create"
          and .objectRef.resource == "projectrequests"
        )
        | "\(.requestReceivedTimestamp) creó proyecto=\(.objectRef.name) code=\(.responseStatus.code)"
      '
done
```

### 10.4. Eliminaciones automáticas (operadores, GitOps)

Si quien elimina es un componente automatizado, el evento sobre `projects` mostrará una service account (no un usuario humano):

```json
{
  "user": {"username": "system:serviceaccount:openshift-gitops:openshift-gitops-argocd-application-controller"},
  "verb": "delete",
  "objectRef": {"resource": "projects", "name": "desarrollo-demo-app"}
}
```

En ese caso el responsable es el componente indicado en `user.username`, no una persona.

---

## 11. Recopilar logs para soporte

```bash
oc adm must-gather -- /usr/bin/gather_audit_logs

tar cvaf must-gather-audit.tar.gz must-gather.local.*
```

---

## 12. Perfiles de auditoría

OpenShift define el nivel de detalle de los logs mediante `spec.audit.profile` en el recurso `APIServer`. Los perfiles aplican a las peticiones del OpenShift API server, Kubernetes API server, OpenShift OAuth API server y OpenShift OAuth server.

Consultar el perfil activo:

```bash
oc get apiserver cluster -o jsonpath='{.spec.audit.profile}{"\n"}'
```


| Perfil                 | Descripción                                                                                                                                                                                               |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Default**            | Registra **solo metadatos** de peticiones de lectura y escritura. No registra el cuerpo de la petición (`requestObject`) excepto en solicitudes de tokens OAuth. Es el perfil por defecto de OpenShift.   |
| **WriteRequestBodies** | Además de los metadatos de todas las peticiones, registra el cuerpo de cada **escritura** (`create`, `update`, `patch`, `delete`, `deletecollection`). Mayor consumo de CPU, memoria e I/O que `Default`. |
| **AllRequestBodies**   | Además de los metadatos, registra el cuerpo de **lecturas y escrituras** (`get`, `list`, `create`, `update`, `patch`). Es el perfil con mayor sobrecarga.                                                 |
| **None**               | No registra ninguna petición, incluidas las de OAuth. Las reglas personalizadas (`customRules`) se ignoran. No recomendado.                                                                               |


Notas adicionales (según documentación de Red Hat):

1. Recursos sensibles (`Secret`, `Route`, `OAuthClient`) se registran solo a nivel de metadatos aunque se use un perfil que incluya cuerpos.
2. Los eventos del OpenShift OAuth server se registran solo a nivel de metadatos.
3. Se pueden definir reglas personalizadas en `spec.audit.customRules` por grupo de autenticación; se evalúan de arriba a abajo y la primera coincidencia aplica.

Con el perfil **Default** es posible identificar quién accedió, creó, modificó o eliminó recursos (incluidos proyectos), aunque no se almacene el YAML completo enviado en la petición.

---

## 13. Resumen de comandos rápidos

```bash
oc login -u admin

# Perfil actual
oc get apiserver cluster -o jsonpath='{.spec.audit.profile}{"\n"}'

# Nodos control plane
oc get nodes -l node-role.kubernetes.io/master= -o name

export MASTER_NODE=ip-10-0-107-138.us-east-2.compute.internal
export USUARIO_AUDITAR=user21
export NOMBRE_PROYECTO=aplicacion-nucleo-datasystems

# Filtrar por usuario (recursos dentro de namespaces: pods, configmaps, etc.)
oc adm node-logs $MASTER_NODE --path=kube-apiserver/audit.log \
  | jq -c --arg u "$USUARIO_AUDITAR" 'select(.user.username == $u)'

# Quién eliminó un proyecto → recurso projects (no namespaces del sistema)
for NODE in $(oc get nodes -l node-role.kubernetes.io/master= -o jsonpath='{.items[*].metadata.name}'); do
  oc adm node-logs "$NODE" --path=kube-apiserver/audit.log 2>/dev/null \
    | jq -c --arg p "$NOMBRE_PROYECTO" '
        select(.verb == "delete" and .objectRef.resource == "projects" and .objectRef.name == $p)
      '
done

# Quién creó un proyecto → recurso projectrequests (no projects del sistema)
for NODE in $(oc get nodes -l node-role.kubernetes.io/master= -o jsonpath='{.items[*].metadata.name}'); do
  oc adm node-logs "$NODE" --path=openshift-apiserver/audit.log 2>/dev/null \
    | jq -c --arg p "$NOMBRE_PROYECTO" '
        select(.verb == "create" and .objectRef.resource == "projectrequests" and .objectRef.name == $p)
      '
done

# Login en consola
oc adm node-logs $MASTER_NODE --path=oauth-server/audit.log \
  | jq -c --arg u "$USUARIO_AUDITAR" '
      select(.annotations["authentication.openshift.io/username"] == $u)
    '
```

---

## 14. Referencias adicionales

- [OpenShift — Viewing audit logs](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/security_and_compliance/audit-log-view)
- [OpenShift — Configuring the audit log policy](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/security_and_compliance/audit-log-policy-config)
- [Kubernetes — Auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Kubernetes — Audit policy](https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/#audit-k8s-io-v1-Policy)
- [Must-gather — gather_audit_logs](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/support/gathering-data-about-your-cluster)

