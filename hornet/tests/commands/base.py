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
        default_host.filesystem.makedir(u'/etc')
        default_host.filesystem.makedir(u'/var')
        default_host.filesystem.makedir(u'/bin')
        default_host.filesystem.makedir(u'/.hidden')
        default_host.filesystem.makedir(u'/etc/init.d')
        default_host.filesystem.create(u'/etc/passwd')
        default_host.filesystem.create(u'/etc/.config')
        default_host.filesystem.create(u'/etc/sysctl.conf')
        default_host.filesystem.create(u'/.hidden/.rcconf')
        default_host.filesystem.create(u'/initrd.img')


if __name__ == '__main__':
    unittest.main()
