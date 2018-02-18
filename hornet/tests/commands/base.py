import os
import tempfile
import unittest
import shutil
import hornet


class BaseTestClass(unittest.TestCase):

    def setUp(self):
        self.working_dir = tempfile.mkdtemp()
        test_config = os.path.join(os.path.dirname(hornet.__file__), 'data', 'default_config.json')
        shutil.copyfile(test_config, os.path.join(self.working_dir, 'config.json'))

    def tearDown(self):
        shutil.rmtree(self.working_dir)

    def create_filesystem(self, honeypot):
        default_host = honeypot.vhosts[honeypot.config.default_hostname]
        default_host.filesystem.makedir('/etc')
        default_host.filesystem.makedir('/var')
        default_host.filesystem.makedir('/bin')
        default_host.filesystem.makedir('/.hidden')
        default_host.filesystem.makedir('/etc/init.d')
        default_host.filesystem.createfile('/etc/passwd')
        default_host.filesystem.createfile('/etc/.config')
        default_host.filesystem.createfile('/etc/sysctl.conf')
        default_host.filesystem.createfile('/.hidden/.rcconf')
        default_host.filesystem.createfile('/initrd.img')


if __name__ == '__main__':
    unittest.main()
