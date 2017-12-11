from cortexutils.analyzer import Analyzer
from censys.certificates import CensysCertificates
from censys.ipv4 import CensysIPv4


class CensysAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        self.__uid = self.get_param(
            'config.uid',
            None,
            'No UID for Censys given. Please add it to the cortex configuration.'
        )
        self.__api_key = self.get_param(
            'config.key',
            None,
            'No API-Key for Censys given. Please add it to the cortex configuration.'
        )

    def search_hosts(self, ip):
        """
        Searches for a host using its ipv4 address

        :param ip: ipv4 address as string
        :type ip: str
        :return: dict
        """
        c = CensysIPv4(api_id=self.__uid, api_secret=self.__api_key)
        return c.view(ip)

    def search_certificate(self, hash):
        """
        Searches for a specific certificate using its hash

        :param hash: certificate hash
        :type hash: str
        :return: dict
        """
        c = CensysCertificates(api_id=self.__uid, api_secret=self.__api_key)
        return c.view(hash)

    def run(self):
        if self.data_type == 'ip':
            self.report(self.search_hosts(self.get_data()))
        elif self.data_type == 'hash':
            self.report(self.search_certificate(self.get_data()))
        else:
            self.error('Data type not supported. Please use this analyzer with data types hash or ip.')


if __name__ == '__main__':
    CensysAnalyzer().run()