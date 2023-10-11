import pytest

import time
import logging

from scapy.all import Packet, BitField, _OTypeField, FieldLenField, PacketListField
import ptf.mask as mask
import ptf.packet as packet
import ptf.testutils as testutils

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0", "t1")
]


class MCD(Packet):
    name = "Midpoint Compress Data (MCD)"
    fields_desc = [
        BitField("timestamp", 0, 8),
        BitField("intfid", 0, 12),
        BitField("load", 0, 4),
    ]


class PathTracing(Packet):
    """
    IPv6 Hop-By-Hop Path Tracing Option, draft-filsfils-spring-path-tracing-04, section #9.1
    
                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                    |  Option Type  |  Opt Data Len |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    ~                          MCD  Stack                           ~
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Reference:
        https://www.ietf.org/archive/id/draft-filsfils-spring-path-tracing-04.html
    """
    name = "Path Tracing Option"
    fields_desc = [_OTypeField("otype", 0x1E, _hbhopts),
                   FieldLenField("optlen", None, length_of="mcdstack", fmt="B"),
                   PacketListField("mcdstack", [], MCD)]

    def alignment_delta(self, curpos):  # alignment requirement : 4n+2
        x = 4
        y = 2
        delta = x * ((curpos - y + x - 1) // x) + y - curpos
        return delta

    def extract_padding(self, p):
        return b"", p


class TestPathTracingMidpoint:
    """
    Base class for Path Tracing Midpoint testing.
    """
    def teardown_path_tracing(self, setup):
        """
        teardown Path Tracing after test by disabling Path Tracing on all interfaces
        :param dut: DUT host object
        :param setup: setup information
        :return:
        """
        logger.info("Disable Path Tracing")
        self.config_path_tracing(setup, ifname="Ethernet8", enable=False)

    def icmpv6_packet_no_hbh_pt(self, setup, ptfadapter):
        """ create ICMPv6 packet for testing """
        return testutils.simple_icmp_packet(
            eth_dst=setup['src_mac'],
            eth_src=ptfadapter.dataplane.get_mac(0, setup['src_pid']),
            ipv6_dst='2001:db8:1::1',
            ipv6_src=setup['src_addr'],
            icmp_type=8,
            icmp_code=0,
            ipv6_hlim=64,
        )

    def icmpv6_packet_with_hbh_pt(self, setup, ptfadapter, interface_id, ts_template, load):
        """ create ICMPv6 packet with Hop-by-Hop Path Tracing Option for testing """
        icmpv6_pkt = self.icmp_packet(setup, ptfadapter)
        hbh_pt = PathTracing(
            mcdstack=[
                MCD(timestamp=ts_template, intfid=interface_id, load=load)
            ]
        )
        return icmpv6_pkt / hbh_pt

    def icmpv6_packet_with_hbh_pt_empty_mcdstack(self, setup, ptfadapter):
        """ create ICMPv6 packet followed by a Hop-by-Hop Path Tracing Option with an empty MCD stack for testing """
        icmpv6_pkt = self.icmp_packet(setup, ptfadapter)
        hbh_pt = PathTracing(
            mcdstack=[

            ]
        )
        return icmpv6_pkt / hbh_pt

    def expected_mask_forward_ipv6_packet(self, pkt):
        """ Return mask for ipv6 packet base forwarding """

        exp_pkt = pkt.copy()
        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
        exp_pkt['IPv6'].hlim = 62

        return exp_pkt

    def expected_mask_path_tracing_push_mcd_packet(self, pkt, interface_id, ts_template, load):
        """ return mask for Path Tracing MCD push operation packet """

        exp_pkt = pkt.copy()
        exp_pkt['IPv6'].hlim -= 1
        exp_pkt['PathTracing'].mcdstack.append(
            MCD(
                interface_id,
                ts_template,
                load
            )
        )
        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')

        return exp_pkt

    def config_path_tracing(self, setup, ifname, enable=True, interface_id=None, ts_template=None):
        """ Enable/disable Path tracing on interface """
        duthost = setup['duthost']

        # Case 1: Disable Path Tracing on interface
        if not enable:
            logger.info('Disabling Path Tracing on interface %s'.format(ifname))
            result = duthost.shell('config interface path-tracing del {}'.format(ifname))
            if result['rc'] != 0:
                pytest.fail('Failed to disable Path Tracing on interface {} : {}'.format(ifname, result['stderr']))
            return

        # Case 2: Enable Path Tracing with default timestamp template
        if ts_template is None:
            logger.info('Enabling Path Tracing on interface %s (interface ID {})'.format(ifname, interface_id))
            result = duthost.shell('config interface path-tracing add {} --interface-id {}'.format(ifname, interface_id))
            if result['rc'] != 0:
                pytest.fail('Failed to enable Path Tracing on interface {} : {}'.format(ifname, result['stderr']))
            return

        # Case 3: Enable Path Tracing with default timestamp template
        logger.info('Enabling Path Tracing on interface %s (interface ID {}, timestamp template "{}")'.format(ifname, interface_id, ts_template))
        result = duthost.shell('config interface path-tracing add {} --interface-id {} --ts-template {}'.format(ifname, interface_id, ts_template))
        if result['rc'] != 0:
            pytest.fail('Failed to enable Path Tracing on interface {} : {}'.format(ifname, result['stderr']))


    def test_base_forwarding(self, setup, ptfadapter):
        """
        Test scenario in which:
            - Path Tracing is disabled on the port
            - The DUT receives a simple ICMPv6 packet

        Expected result:
            - The packet is forwarded without any modification
        """
        dst_pid = setup['dst_pid']
        src_pid = setup['src_pid']

        self.config_path_tracing(setup, ifname='Ethernet8', enable=False)

        time.sleep(2)

        pkt = self.icmpv6_packet_no_hbh_pt(setup, ptfadapter)
        exp_pkt = self.expected_mask_forward_ipv6_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, src_pid, pkt)
        try:
            res = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=[dst_pid])
            logger.info(res)
        except Exception as e:
            self.teardown_path_tracing(setup)
            pytest.fail('Simple packet forwarding test failed \n' + str(e))

        self.teardown_path_tracing(setup)

    def test_path_tracing_disabled(self, setup, ptfadapter):
        """
        Test scenario in which:
            - Path Tracing is disabled on the port
            - The DUT receives an ICMPv6 packet followed by a HbH-PT with non-empty MCD stack

        Expected result:
            - The packet is forwarded without any modification
        """
        dst_pid = setup['dst_pid']
        src_pid = setup['src_pid']

        self.config_path_tracing(setup, ifname='Ethernet8', enable=False)

        time.sleep(2)

        pkt = self.icmpv6_packet_with_hbh_pt(setup, ptfadapter)
        exp_pkt = self.expected_mask_forward_ipv6_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, src_pid, pkt)
        try:
            res = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=[dst_pid])
            logger.info(res)
        except Exception as e:
            self.teardown_path_tracing(setup)
            pytest.fail('Path Tracing disabled test failed \n' + str(e))

        self.teardown_path_tracing(setup)

    def test_path_tracing_no_hbh_pt(self, setup, ptfadapter):
        """
        Test scenario in which:
            - Path Tracing is enabled on the port
            - The DUT receives an ICMPv6 packet that does not contains a HbH-PT

        Expected result:
            - The packet is forwarded without any modification
        """
        dst_pid = setup['dst_pid']
        src_pid = setup['src_pid']

        self.config_path_tracing(setup, ifname='Ethernet8', enable=True, interface_id=128)

        time.sleep(2)

        pkt = self.icmpv6_packet_no_hbh_pt(setup, ptfadapter)
        exp_pkt = self.expected_mask_forward_ipv6_packet(pkt)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, src_pid, pkt)
        try:
            res = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=[dst_pid])
            logger.info(res)
        except Exception as e:
            self.teardown_path_tracing(setup)
            pytest.fail('"No Hop-by-Hop Path Tracing Option" test failed \n' + str(e))

        self.teardown_path_tracing(setup)

    def test_path_tracing_empty_mcd_stack(self, setup, ptfadapter):
        """
        Test scenario in which:
            - Path Tracing is enabled on the port
            - The DUT receives an ICMPv6 packet followed by a HbH-PT with an empty MCD stack

        Expected result:
            - The DUT pushes a new MCD before forwarding the packet on the outgoing interface
        """
        dst_pid = setup['dst_pid']
        src_pid = setup['src_pid']

        self.config_path_tracing(setup, ifname='Ethernet8', enable=True, interface_id=128)

        time.sleep(2)

        pkt = self.icmpv6_packet_with_hbh_pt_empty_mcdstack(setup, ptfadapter)
        exp_pkt = self.expected_mask_path_tracing_push_mcd_packet(pkt, interface_id=128, ts_template='template3', load=111)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, src_pid, pkt)
        try:
            res = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=[dst_pid])
            logger.info(res)
        except Exception as e:
            self.teardown_path_tracing(setup)
            pytest.fail('"Empty MCD stack" test failed \n' + str(e))

        self.teardown_path_tracing(setup)

    def test_path_tracing_default_ts_template(self, setup, ptfadapter):
        """
        Test scenario in which:
            - Path Tracing is enabled on the port
            - Default timestamp is used
            - The DUT receives an ICMPv6 packet followed by a HbH-PT with a non-empty MCD stack

        Expected result:
            - The DUT pushes a new MCD before forwarding the packet on the outgoing interface
        """
        dst_pid = setup['dst_pid']
        src_pid = setup['src_pid']

        self.config_path_tracing(setup, ifname='Ethernet8', enable=True, interface_id=128)

        time.sleep(2)

        pkt = self.icmpv6_packet_with_hbh_pt(setup, ptfadapter)
        exp_pkt = self.expected_mask_path_tracing_push_mcd_packet(pkt, interface_id=128, ts_template='template3', load=111)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, src_pid, pkt)
        try:
            res = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=[dst_pid])
            logger.info(res)
        except Exception as e:
            self.teardown_path_tracing(setup)
            pytest.fail('"Non Empty MCD stack" test failed \n' + str(e))

        self.teardown_path_tracing(setup)

    def test_path_tracing_non_default_ts_template(self, setup, ptfadapter):
        """
        Test scenario in which:
            - Path Tracing is enabled on the port
            - Non-default timestamp is used
            - The DUT receives an ICMPv6 packet followed by a HbH-PT with a non-empty MCD stack

        Expected result:
            - The DUT pushes a new MCD before forwarding the packet on the outgoing interface
        """
        dst_pid = setup['dst_pid']
        src_pid = setup['src_pid']

        self.config_path_tracing(setup, ifname='Ethernet8', enable=True, interface_id=128, ts_template="template1")

        time.sleep(2)

        pkt = self.icmpv6_packet_with_hbh_pt(setup, ptfadapter)
        exp_pkt = self.expected_mask_path_tracing_push_mcd_packet(pkt, interface_id=128, ts_template='template1', load=111)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, src_pid, pkt)
        try:
            res = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=[dst_pid])
            logger.info(res)
        except Exception as e:
            self.teardown_path_tracing(setup)
            pytest.fail('"Non default template" test failed \n' + str(e))

        self.teardown_path_tracing(setup)
