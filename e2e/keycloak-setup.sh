#!/bin/bash
# Idempotent dev-Keycloak setup for the browser tests: realm jasca, login client (department + groups mappers, client roles),
# sync service client, users. Run inside the Keycloak container, values come from e2e/.env:
#   docker exec -i -e KC_ADMIN_PASSWORD=... [-e ...] <container> bash -s < e2e/keycloak-setup.sh
set -e
: "${KC_ADMIN_PASSWORD:?}" "${KC_USER_PASSWORD:?}" "${KC_CLIENT_SECRET:?}" "${KC_SYNC_SECRET:?}"
K=/opt/keycloak/bin/kcadm.sh
R=${KC_REALM:-jasca}
BASES=${KC_REDIRECT_BASES:-http://localhost:18301}   # space separated origins the app is served from
$K config credentials --server http://localhost:8080 --realm master --user "${KC_ADMIN:-admin}" --password "$KC_ADMIN_PASSWORD" >/dev/null

$K get realms/$R >/dev/null 2>&1 || $K create realms -s realm=$R -s enabled=true >/dev/null

URIS=""; ORIGINS=""
for b in $BASES; do URIS="$URIS${URIS:+,}\"$b/*\""; ORIGINS="$ORIGINS${ORIGINS:+,}\"$b\""; done
cid() { $K get clients -r $R -q clientId=$1 --fields id --format csv --noquotes; }
if [ -z "$(cid jasca)" ]; then
  $K create clients -r $R -s clientId=jasca -s enabled=true -s publicClient=false -s standardFlowEnabled=true >/dev/null
fi
CID=$(cid jasca)
mapper() { # name type extra-config...
  $K get clients/$CID/protocol-mappers/models -r $R --fields name --format csv --noquotes | grep -qx "$1" && return 0
  local n=$1 t=$2; shift 2
  $K create clients/$CID/protocol-mappers/models -r $R -s name=$n -s protocol=openid-connect -s protocolMapper=$t \
    -s 'config."id.token.claim"=true' -s 'config."access.token.claim"=true' -s 'config."userinfo.token.claim"=true' "$@" >/dev/null
}
mapper groups oidc-group-membership-mapper -s 'config."full.path"=true' -s 'config."claim.name"=groups'
# department user attribute -> ID token claim; Multivalued on, so a user can belong to several departments
mapper department oidc-usermodel-attribute-mapper -s 'config."user.attribute"=department' -s 'config."claim.name"=department' \
  -s 'config."jsonType.label"=String' -s 'config."multivalued"=true'
# Keycloak >= 24 keeps only declared attributes. Unmanaged attributes must be ADMIN_EDIT ("Only administrators can write"),
# never ENABLED: a user who could edit department in the account console could join any department's restrictions.
UP=$(mktemp)
if $K get users/profile -r $R >"$UP" 2>/dev/null; then
  if grep -q '"unmanagedAttributePolicy"' "$UP"; then
    sed -i 's/"unmanagedAttributePolicy" *: *"[A-Z_]*"/"unmanagedAttributePolicy" : "ADMIN_EDIT"/' "$UP"
  else
    sed -i '1s/^{/{"unmanagedAttributePolicy":"ADMIN_EDIT",/' "$UP"
  fi
  $K update users/profile -r $R -f "$UP" >/dev/null
fi
rm -f "$UP"
$K update clients/$CID -r $R -s secret="$KC_CLIENT_SECRET" -s "redirectUris=[$URIS]" -s "webOrigins=[$ORIGINS]" >/dev/null
for role in jasca-admin jasca-security; do
  $K get clients/$CID/roles/$role -r $R >/dev/null 2>&1 || $K create clients/$CID/roles -r $R -s name=$role >/dev/null
done

if [ -z "$(cid jasca-sync)" ]; then
  $K create clients -r $R -s clientId=jasca-sync -s enabled=true -s publicClient=false -s serviceAccountsEnabled=true -s standardFlowEnabled=false >/dev/null
fi
$K update clients/$(cid jasca-sync) -r $R -s secret="$KC_SYNC_SECRET" >/dev/null
$K add-roles -r $R --uusername service-account-jasca-sync --cclientid realm-management --rolename view-users --rolename query-groups >/dev/null 2>&1 || true

uid() { $K get users -r $R -q username=$1 --fields id --format csv --noquotes; }
mkuser() { # username first last
  [ -n "$(uid $1)" ] || $K create users -r $R -s username=$1 -s enabled=true -s firstName="$2" -s lastName="$3" -s email=$1@example.test -s emailVerified=true >/dev/null
  $K set-password -r $R --username $1 --new-password "$KC_USER_PASSWORD"
}
mkuser kim 민지 김; mkuser lee 서준 이; mkuser park 관리 박
$K update users/$(uid kim) -r $R -s 'attributes.department=["보안실/취약점팀"]' >/dev/null
$K update users/$(uid lee) -r $R -s 'attributes.department=["개발본부/플랫폼팀"]' >/dev/null
$K add-roles -r $R --uusername kim --cclientid jasca --rolename jasca-security >/dev/null
echo "keycloak ok"
