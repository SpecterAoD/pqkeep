"""Negative tests for an offline, credential-free container sandbox."""
import copy
import unittest

from verify_opencode_sandbox import compliant


def safe():
    return {
        "Config": {"User": "10001:10001", "Entrypoint": ["/bin/true"], "Env": []},
        "HostConfig": {
            "ReadonlyRootfs": True, "Privileged": False,
            "NetworkMode": "none", "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "PidMode": "", "IpcMode": "private", "CgroupnsMode": "private",
            "Memory": 256 * 1024 * 1024, "PidsLimit": 32,
            "NanoCpus": 1_000_000_000, "Binds": None, "Devices": [],
            "PortBindings": {}, "ExtraHosts": None, "Dns": [],
            "Mounts": [],
        },
    }


class SandboxTests(unittest.TestCase):
    def test_offline_container(self):
        self.assertTrue(compliant(safe()))

    def test_network_forbidden(self):
        for mode in ("host", "bridge", "container:other"):
            with self.subTest(mode=mode):
                data = safe()
                data["HostConfig"]["NetworkMode"] = mode
                self.assertFalse(compliant(data))

    def test_privileged_forbidden(self):
        data = safe()
        data["HostConfig"]["Privileged"] = True
        self.assertFalse(compliant(data))

    def test_root_forbidden(self):
        for user in ("", "root", "0", "0:0"):
            data = safe()
            data["Config"]["User"] = user
            self.assertFalse(compliant(data))

    def test_secrets_forbidden(self):
        for key in ("GEMINI_API_KEY", "GITHUB_TOKEN", "GH_TOKEN"):
            data = safe()
            data["Config"]["Env"] = [key + "=secret"]
            self.assertFalse(compliant(data))

    def test_host_mount_forbidden(self):
        data = safe()
        data["HostConfig"]["Binds"] = ["/:/host:ro"]
        self.assertFalse(compliant(data))

    def test_caps_required(self):
        data = safe()
        data["HostConfig"]["CapDrop"] = []
        self.assertFalse(compliant(data))

    def test_readonly_required(self):
        data = safe()
        data["HostConfig"]["ReadonlyRootfs"] = False
        self.assertFalse(compliant(data))

    def test_resource_limits_required(self):
        data = safe()
        data["HostConfig"]["PidsLimit"] = 0
        self.assertFalse(compliant(data))

    def test_arbitrary_environment_denied(self):
        for item in ("CUSTOM_TOKEN=secret", "HTTPS_PROXY=http://host",
                     "PATH=/bin\\nGITHUB_TOKEN=secret", "SECRET=abc"):
            with self.subTest(item=item):
                data = safe()
                data["Config"]["Env"] = [item]
                self.assertFalse(compliant(data))

    def test_known_nonsecret_environment(self):
        data = safe()
        data["Config"]["Env"] = ["PATH=/usr/bin", "LANG=C.UTF-8"]
        self.assertTrue(compliant(data))

    def test_added_capabilities_denied(self):
        data = safe()
        data["HostConfig"]["CapAdd"] = ["NET_ADMIN"]
        self.assertFalse(compliant(data))

    def test_host_user_namespace_denied(self):
        data = safe()
        data["HostConfig"]["UsernsMode"] = "host"
        self.assertFalse(compliant(data))

    def test_extra_hosts_forbidden(self):
        data = safe()
        data["HostConfig"]["ExtraHosts"] = ["gateway:127.0.0.1"]
        self.assertFalse(compliant(data))


if __name__ == "__main__":
    unittest.main()
