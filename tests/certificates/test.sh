#!/usr/bin/env bash
set -ex

CERTS_DIR="$SCRIPT_DIR/certs"

export_image_trust_store() {
  local output_file=${1:?Missed mandatory parameter: output file}
  local fs_mode=${2:?Missed mandatory parameter: fs mode}
  shift 2
  echo "Export certificate list from: $IMAGE, FS mode: ${fs_mode}"
  # shellcheck disable=SC2046
  docker run "${@}" --rm \
      -v "${CERTS_DIR}":/tmp/cert/ \
      $(read_only_params "$fs_mode") \
      "$IMAGE" \
      cat /etc/ssl/certs/ca-certificates.crt >"${output_file}.crt"

  # extract certificates list from certs file
  openssl crl2pkcs7 -nocrl -certfile "${output_file}.crt" | openssl pkcs7 -print_certs -noout >"${output_file}"
}

test_restore_volumes_data() {
  echo "Test: restore_volumes_data restores certs to a simulated emptyDir (BusyBox cp -Rn fix)"
  # This directly tests the core bugfix: the old code used
  #   cp -Rn /app/volumes/certs/. /etc/ssl/certs
  # which silently copies zero files on BusyBox 1.37+ because the src/. idiom causes cp to
  # compute the destination as dest/. — which already exists — and -n (no-clobber) aborts.
  # The fix uses glob expansion so each file is addressed individually:
  #   cp -Rn /app/volumes/certs/* /app/volumes/certs/.[!.]* /etc/ssl/certs/
  #
  # The test overrides the entrypoint to:
  #  1. clear /etc/ssl/certs (simulate Kubernetes emptyDir — empty at container start)
  #  2. extract and run only restore_volumes_data() from the image's entrypoint
  #  3. assert that cert files were actually copied back
  local count
  count=$(docker run --rm --entrypoint=bash "${@}" "$IMAGE" \
    -c '
      rm -rf /etc/ssl/certs/* /etc/ssl/certs/java 2>/dev/null || true
      eval "$(awk "/^restore_volumes_data\(\)/,/^\}$/ {print; if (/^\}$/) exit}" /usr/bin/entrypoint.sh)"
      restore_volumes_data
      find /etc/ssl/certs -type f 2>/dev/null | wc -l
    ')
  count="${count//[[:space:]]/}"
  [ "${count:-0}" -gt 0 ] || fail "restore_volumes_data restored 0 files — BusyBox cp -Rn /app/volumes/certs/. bug is present"
}

test_load_certificates_java_keystore_fallback() {
  echo "Test: load_certificates fallback creates java/cacerts when java/ subdir is absent (Kubernetes emptyDir)"
  # Kubernetes mounts /etc/ssl/certs as emptyDir, so the java/ subdir does not pre-exist.
  # When update-ca-certificates fails (e.g. OpenShift SCC), the fallback must mkdir -p first,
  # otherwise BusyBox cp cannot create java/cacerts and keytool fails with "Not a directory".
  #
  # We cannot directly simulate "java/ missing" in local Docker/Podman because both
  # /etc/ssl/certs and /etc/ssl/certs/java are declared as separate VOLUMEs in the image, so
  # the nested java/ volume is always mounted even with --tmpfs /etc/ssl/certs.
  # Instead, we extract load_certificates from each image via awk and redirect the java/
  # path to /tmp/testjava (a fresh dir with no java/ subdir pre-created), then verify
  # whether the function creates /tmp/testjava/cacerts.
  local result
  result=$(docker run --rm --entrypoint=bash "${@}" "$IMAGE" \
    -c '
      log() { true; }
      eval "$(awk "/^load_certificates\(\)/,/^\}$/ {print; if (/^\}$/) exit}" /usr/bin/entrypoint.sh \
            | sed "s|/etc/ssl/certs/java|/tmp/testjava|g")"
      update-ca-certificates() { return 1; }
      load_certificates 2>/dev/null
      [ -f /tmp/testjava/cacerts ] && echo "PASS" || echo "FAIL"
    ')
  result="${result//[[:space:]]/}"
  [ "$result" = "PASS" ] || fail "load_certificates fallback did not create java/cacerts: got '$result'"
}

export_image_trust_store_with_emptydir() {
  local output_file=${1:?Missed mandatory parameter: output file}
  shift
  echo "Export certificate list from: $IMAGE, emptyDir at /etc/ssl/certs (restore_volumes_data integration test)"
  # --tmpfs /etc/ssl/certs simulates a Kubernetes emptyDir mount over the VOLUME-declared path.
  # restore_volumes_data() must restore certs from /app/volumes/certs/ before load_certificates()
  # runs update-ca-certificates to rebuild the bundle.
  docker run "${@}" --rm \
      -v "${CERTS_DIR}":/tmp/cert/ \
      --tmpfs /etc/ssl/certs \
      "$IMAGE" \
      cat /etc/ssl/certs/ca-certificates.crt >"${output_file}.crt"

  openssl crl2pkcs7 -nocrl -certfile "${output_file}.crt" | openssl pkcs7 -print_certs -noout >"${output_file}"
}

export_java_keystore() {
  local output_file=${1:?Missed mandatory parameter: output file}
  local fs_mode=${2:?Missed mandatory parameter: fs mode}
  shift 2
  echo "Export certificate list from: $IMAGE, FS mode: ${fs_mode}"
  # shellcheck disable=SC2046
  docker run "${@}" --rm \
      -v "${CERTS_DIR}":/tmp/cert/ \
      -e CERTIFICATE_FILE_PASSWORD=abc12345 \
      $(read_only_params "$fs_mode") \
      "$IMAGE" \
      keytool -list -cacerts -storepass abc12345 -v >"${output_file}"
}

assert_tests() {
  local output_file=$1
  <"$output_file" grep -e "CN\s*=\s*qubership-test" >/dev/null || fail "cert from testcert.pem is missed"
  <"$output_file" grep -e "CN\s*=\s*valid2" >/dev/null || fail "cert from multi_cert.crt is missed"
  <"$output_file" grep -e "CN\s*=\s*valid1" >/dev/null || fail "cert from multi_cert.crt is missed"
  <"$output_file" grep -e "CN\s*=\s*testcerts.com" >/dev/null || fail "cert from test-k8s-ca.crt is missed"
}

EXPORTED_CERTS_FILE=$(mktemp /tmp/certificates-test.XXXXXX)
export_image_trust_store "$EXPORTED_CERTS_FILE" rw
assert_tests "$EXPORTED_CERTS_FILE"

# Test the same with volume mounted to cert path directory in read-only mode
export_image_trust_store "$EXPORTED_CERTS_FILE" ro
assert_tests "$EXPORTED_CERTS_FILE"

# OpenShift case with random UID
export_image_trust_store "$EXPORTED_CERTS_FILE" ro -u 10009000
assert_tests "$EXPORTED_CERTS_FILE"

# Unit test: restore_volumes_data in isolation, before update-ca-certificates can compensate.
# RED on the broken image (BusyBox cp -Rn /. copies 0 files), GREEN on the fixed image.
test_restore_volumes_data
test_restore_volumes_data -u 10009000

# Integration test: emptyDir mount over /etc/ssl/certs with the full entrypoint.
# Validates the end-to-end flow: restore_volumes_data → load_certificates → certs available.
export_image_trust_store_with_emptydir "$EXPORTED_CERTS_FILE"
assert_tests "$EXPORTED_CERTS_FILE"

# OpenShift case with random UID
export_image_trust_store_with_emptydir "$EXPORTED_CERTS_FILE" -u 10009000
assert_tests "$EXPORTED_CERTS_FILE"

if [[ "$IMAGE" == *java* ]]; then
  echo "Test certificates imported in JKS"
  export_java_keystore "$EXPORTED_CERTS_FILE" rw
  assert_tests "$EXPORTED_CERTS_FILE"

  export_java_keystore "$EXPORTED_CERTS_FILE" ro
  assert_tests "$EXPORTED_CERTS_FILE"

  # OpenShift case with random UID
  export_java_keystore "$EXPORTED_CERTS_FILE" rw -u 10009000
  assert_tests "$EXPORTED_CERTS_FILE"

  export_java_keystore "$EXPORTED_CERTS_FILE" ro -u 10009000
  assert_tests "$EXPORTED_CERTS_FILE"

  # Unit test: fallback path in load_certificates creates java/cacerts when java/ subdir is absent.
  test_load_certificates_java_keystore_fallback
fi