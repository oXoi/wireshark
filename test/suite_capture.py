#
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Capture tests'''

import glob
import hashlib
import os
import socket
import subprocess
import subprocesstest
from subprocesstest import cat_dhcp_command, cat_cap_file_command, count_output, grep_output, check_packet_count
from suite_text2pcap import check_capinfos_info
import sys
import threading
import time
import uuid
import sysconfig
import pytest

capture_duration = 5

testout_pcap = 'testout.pcap'
testout_pcapng = 'testout.pcapng'
snapshot_len = 96

class UdpTrafficGenerator(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.stopped = False

    def run(self):
        while not self.stopped:
            time.sleep(.05)
            self.sock.sendto(b'Wireshark test\n', ('127.0.0.1', 9))

    def stop(self):
        if not self.stopped:
            self.stopped = True
            self.join()


@pytest.fixture
def traffic_generator():
    '''
    Traffic generator factory. Invoking it returns a tuple (start_func, cfilter)
    where cfilter is a capture filter to match the generated traffic.
    start_func can be invoked to start generating traffic and returns a function
    which can be used to stop traffic generation early.
    Currently generates a bunch of UDP traffic to localhost.
    '''
    threads = []
    def start_processes():
        thread = UdpTrafficGenerator()
        thread.start()
        threads.append(thread)
        return thread.stop
    try:
        yield start_processes, 'udp port 9'
    finally:
        for thread in threads:
            thread.stop()


@pytest.fixture(scope='session')
def wireshark_k(wireshark_command):
    return tuple(list(wireshark_command) + ['-k'])


def capture_command(*args, shell=False, quoted=False):
    cmd_args = list(args)
    if type(cmd_args[0]) != str:
        # Assume something like ['wireshark', '-k']
        cmd_args = list(cmd_args[0]) + list(cmd_args)[1:]
    if shell:
        cmd_args[0] = f'"{cmd_args[0]}"'
        cmd_args = ' '.join(cmd_args)
    return cmd_args


@pytest.fixture
def check_capture_10_packets(capture_interface, cmd_capinfos, traffic_generator, result_file):
    start_traffic, cfilter = traffic_generator
    def check_capture_10_packets_real(self, cmd=None, to_stdout=False, env=None):
        assert cmd is not None
        testout_file = result_file(testout_pcap)
        stop_traffic = start_traffic()
        if to_stdout:
            subprocesstest.check_run(capture_command(cmd,
                '-i', '"{}"'.format(capture_interface),
                '-p',
                '-w', '-',
                '-c', '10',
                '-a', 'duration:{}'.format(capture_duration),
                '-f', '"{}"'.format(cfilter),
                '>', testout_file,
                shell=True
            ),
            shell=True, env=env)
        else:
            subprocesstest.check_run(capture_command(cmd,
                '-i', capture_interface,
                '-p',
                '-w', testout_file,
                '-c', '10',
                '-a', 'duration:{}'.format(capture_duration),
                '-f', cfilter,
            ), env=env)
        stop_traffic()
        check_packet_count(cmd_capinfos, 10, testout_file)
    return check_capture_10_packets_real


@pytest.fixture
def check_capture_fifo(cmd_capinfos, result_file):
    if sys.platform == 'win32':
        pytest.skip('Test requires OS fifo support.')

    def check_capture_fifo_real(self, cmd=None, env=None):
        assert cmd is not None
        testout_file = result_file(testout_pcap)
        fifo_file = result_file('testout.fifo')
        try:
            # If a previous test left its fifo laying around, e.g. from a failure, remove it.
            os.unlink(fifo_file)
        except Exception:
            pass
        os.mkfifo(fifo_file)
        slow_dhcp_cmd = cat_dhcp_command('slow')
        fifo_proc = subprocess.Popen(
            ('{0} > {1}'.format(slow_dhcp_cmd, fifo_file)),
            shell=True)
        subprocesstest.check_run(capture_command(cmd,
            '-i', fifo_file,
            '-p',
            '-w', testout_file,
            '-a', 'duration:{}'.format(capture_duration),
        ), env=env)
        fifo_proc.kill()
        assert os.path.isfile(testout_file)
        check_packet_count(cmd_capinfos, 8, testout_file)
    return check_capture_fifo_real


@pytest.fixture
def check_capture_stdin(cmd_capinfos, result_file):
    # Capturing always requires dumpcap, hence the dependency on it.
    def check_capture_stdin_real(self, cmd=None, env=None):
        # Similar to suite_io.check_io_4_packets.
        assert cmd is not None
        testout_file = result_file(testout_pcap)
        slow_dhcp_cmd = cat_dhcp_command('slow')
        capture_cmd = capture_command(cmd,
            '-i', '-',
            '-w', f'"{testout_file}"',
            '-a', 'duration:{}'.format(capture_duration),
            shell=True
        )
        is_gui = type(cmd) != str and '-k' in cmd[0]
        if is_gui:
            capture_cmd += ' --log-level=info'
        if sysconfig.get_platform().startswith('mingw'):
            pytest.skip('FIXME Pipes are broken with the MSYS2 shell')
        pipe_proc = subprocesstest.check_run(slow_dhcp_cmd + ' | ' + capture_cmd, shell=True, capture_output=True, env=env)
        if is_gui:
            # Wireshark uses stdout and not stderr for diagnostic messages
            # XXX: Confirm this
            assert grep_output(pipe_proc.stdout, 'Wireshark is up and ready to go'), 'No startup message.'
            assert grep_output(pipe_proc.stdout, 'Capture started'), 'No capture start message.'
            assert grep_output(pipe_proc.stdout, 'Capture stopped'), 'No capture stop message.'
        assert os.path.isfile(testout_file)
        check_packet_count(cmd_capinfos, 8, testout_file)
    return check_capture_stdin_real


@pytest.fixture
def check_capture_read_filter(capture_interface, traffic_generator, cmd_capinfos, result_file):
    start_traffic, cfilter = traffic_generator
    def check_capture_read_filter_real(self, cmd=None, env=None):
        assert cmd is not None
        testout_file = result_file(testout_pcap)
        stop_traffic = start_traffic()
        subprocesstest.check_run(capture_command(cmd,
            '-i', capture_interface,
            '-p',
            '-w', testout_file,
            '-2',
            '-R', 'dcerpc.cn_call_id==123456', # Something unlikely.
            '-c', '10',
            '-a', 'duration:{}'.format(capture_duration),
            '-f', cfilter,
        ), env=env)
        stop_traffic()
        check_packet_count(cmd_capinfos, 0, testout_file)
    return check_capture_read_filter_real

@pytest.fixture
def check_capture_snapshot_len(capture_interface, cmd_tshark, traffic_generator, cmd_capinfos, result_file):
    start_traffic, cfilter = traffic_generator
    def check_capture_snapshot_len_real(self, cmd=None, env=None):
        assert cmd is not None
        stop_traffic = start_traffic()
        testout_file = result_file(testout_pcap)
        subprocesstest.check_run(capture_command(cmd,
            '-i', capture_interface,
            '-p',
            '-w', testout_file,
            '-s', str(snapshot_len),
            '-a', 'duration:{}'.format(capture_duration),
            '-f', cfilter,
        ), env=env)
        stop_traffic()
        assert os.path.isfile(testout_file)

        # Use tshark to filter out all packets larger than 68 bytes.
        testout2_file = result_file('testout2.pcap')

        subprocesstest.check_run((cmd_tshark,
            '-r', testout_file,
            '-w', testout2_file,
            '-Y', 'frame.cap_len>{}'.format(snapshot_len),
        ), env=env)
        check_packet_count(cmd_capinfos, 0, testout2_file)
    return check_capture_snapshot_len_real


@pytest.fixture
def check_dumpcap_autostop_stdin(cmd_dumpcap, cmd_capinfos, result_file):
    def check_dumpcap_autostop_stdin_real(self, packets=None, filesize=None, env=None):
        # Similar to check_capture_stdin.
        testout_file = result_file(testout_pcap)
        cat100_dhcp_cmd = cat_dhcp_command('cat100')
        condition='oops:invalid'

        if packets is not None:
            condition = 'packets:{}'.format(packets)
        elif filesize is not None:
            condition = 'filesize:{}'.format(filesize)
        else:
            raise AssertionError('Need one of packets or filesize')

        cmd_ = '"{}"'.format(cmd_dumpcap)
        capture_cmd = ' '.join((cmd_,
            '-i', '-',
            '-w', testout_file,
            '-a', condition,
        ))
        if sysconfig.get_platform().startswith('mingw'):
            pytest.skip('FIXME Pipes are broken with the MSYS2 shell')
        subprocesstest.check_run(cat100_dhcp_cmd + ' | ' + capture_cmd, shell=True, env=env)
        assert os.path.isfile(testout_file)

        if packets is not None:
            check_packet_count(cmd_capinfos, packets, testout_file)
        elif filesize is not None:
            capturekb = os.path.getsize(testout_file) / 1000
            assert capturekb >= filesize
    return check_dumpcap_autostop_stdin_real


@pytest.fixture
def check_dumpcap_ringbuffer_stdin(cmd_dumpcap, cmd_capinfos, result_file):
    def check_dumpcap_ringbuffer_stdin_real(self, packets=None, filesize=None, env=None):
        # Similar to check_capture_stdin.
        rb_unique = 'dhcp_rb_' + uuid.uuid4().hex[:6] # Random ID
        testout_file = result_file('testout.{}.pcapng'.format(rb_unique))
        testout_glob = result_file('testout.{}_*.pcapng'.format(rb_unique))
        cat100_dhcp_cmd = cat_dhcp_command('cat100')
        condition='oops:invalid'

        if packets is not None:
            condition = 'packets:{}'.format(packets)
        elif filesize is not None:
            condition = 'filesize:{}'.format(filesize)
        else:
            raise AssertionError('Need one of packets or filesize')

        cmd_ = '"{}"'.format(cmd_dumpcap)
        capture_cmd = ' '.join((cmd_,
            '-i', '-',
            '-w', testout_file,
            '-a', 'files:2',
            '-b', condition,
        ))
        if sysconfig.get_platform().startswith('mingw'):
            pytest.skip('FIXME Pipes are broken with the MSYS2 shell')
        subprocesstest.check_run(cat100_dhcp_cmd + ' | ' + capture_cmd, shell=True, env=env)

        rb_files = glob.glob(testout_glob)
        assert len(rb_files) == 2

        for rbf in rb_files:
            assert os.path.isfile(rbf)
            if packets is not None:
                check_packet_count(cmd_capinfos, packets, rbf)
            elif filesize is not None:
                capturekb = os.path.getsize(rbf) / 1000
                assert capturekb >= filesize
    return check_dumpcap_ringbuffer_stdin_real


@pytest.fixture
def check_dumpcap_pcapng_sections(cmd_dumpcap, cmd_tshark, cmd_capinfos, capture_file, result_file):
    if sys.platform == 'win32':
        pytest.skip('Test requires OS fifo support.')
    def check_dumpcap_pcapng_sections_real(self, multi_input=False, multi_output=False, mixed_endian=False, be_first=False, env=None):

        # many_interfaces.pcapng.1 : 64 packets written by "Passthrough test #1"
        # many_interfaces.pcapng.2 : 15 packets written by "Passthrough test #2"
        # many_interfaces.pcapng.3 : 9 packets written by "Passthrough test #3"
        # Each has 11 interfaces and is Little Endian.
        # dhcp_big_endian.pcapng : 4 packets, Big Endian, 1 IDB UA "pcap_writer.lua"
        # aka Big Endian test001.pcapng from https://github.com/hadrielk/pcapng-test-generator/
        # All of these source files have a single SHB and the IDBs immediately
        # after the SHB and before and EPBs.

        # It would be good to add another (longer) Big Endian file, to test
        # Big Endian-only multiple inputs.

        # Make sure we always test multiple SHBs in an input.
        in_files_l = [ [
            capture_file('many_interfaces.pcapng.1'),
            capture_file('many_interfaces.pcapng.2')
            ] ]

        # Currently byte swapped SHBs are only supported as passthrough;
        # i.e., with a single input. So with multi_input we add a third
        # Little Endian file.
        if multi_input:
            in_files_l.append([ capture_file('many_interfaces.pcapng.3') ])

        if mixed_endian:
            if be_first:
                in_files_l[0].insert(0, capture_file('dhcp_big_endian.pcapng'))
            else:
                in_files_l[0].append(capture_file('dhcp_big_endian.pcapng'))

        fifo_files = []
        fifo_procs = []
        # Default values for our validity tests
        check_val_d = {
            'filename': None,
            'packet_count': 0,
            'idb_count': 0,
            'userappl_list': [],
        }
        check_vals = [ check_val_d.copy() ]

        autostop_packets = 40

        for in_files in in_files_l:
            fifo_file = result_file('dumpcap_pcapng_sections_{}.fifo'.format(len(fifo_files) + 1))
            fifo_files.append(fifo_file)
            # If a previous test left its fifo laying around, e.g. from a failure, remove it.
            try:
                os.unlink(fifo_file)
            except Exception: pass
            os.mkfifo(fifo_file)
            cat_cmd = cat_cap_file_command(in_files)
            fifo_procs.append(subprocess.Popen(('{0} > {1}'.format(cat_cmd, fifo_file)), shell=True))

            for in_file in in_files:
                cap_info = check_capinfos_info(cmd_capinfos, in_file)
                check_vals[-1]['packet_count'] += cap_info['packets']
                check_vals[-1]['idb_count'] += cap_info['interfaces']
                if not multi_input:
                    check_vals[-1]['userappl_list'].extend(cap_info.get('userappl', []))
                if multi_output and check_vals[-1]['packet_count'] >= autostop_packets:
                    # XXX - We happen to know for each of our input files there
                    # is but one SHB and all IDBs appear before any EPBs, thus
                    # all IDBs (and User Application opts, for SHB passthrough)
                    # should be present if any of its packets are in a given
                    # output file. With more complicated pcapng files, at best
                    # for output files before the last we could only set bounds
                    # for the number of IDBs and User Application options.
                    check_vals.append(check_val_d.copy())
                    check_vals[-1]['packet_count'] = check_vals[-2]['packet_count'] - autostop_packets
                    check_vals[-2]['packet_count'] = autostop_packets
                    if multi_input:
                        check_vals[-1]['idb_count'] = check_vals[-2]['idb_count']
                    else:
                        check_vals[-1]['idb_count'] = cap_info['interfaces']
                        check_vals[-1]['userappl_list'] = cap_info.get('userappl', [])

        if multi_output:
            rb_unique = 'sections_rb_' + uuid.uuid4().hex[:6] # Random ID
            testout_file = result_file('testout.{}.pcapng'.format(rb_unique))
            testout_glob = result_file('testout.{}_*.pcapng'.format(rb_unique))
            # check_vals[]['filename'] will be filled in below
        else:
            testout_file = result_file(testout_pcapng)
            check_vals[0]['filename'] = testout_file

        # Capture commands
        capture_cmd_args = ['-w', testout_file]
        for fifo_file in fifo_files:
            capture_cmd_args.append('-i')
            capture_cmd_args.append(fifo_file)
        if multi_output:
            capture_cmd_args.append('-b')
            capture_cmd_args.append(f'packets:{autostop_packets}')

        capture_cmd = capture_command(cmd_dumpcap, *capture_cmd_args)

        subprocesstest.check_run(capture_cmd, env=env)
        for fifo_proc in fifo_procs: fifo_proc.kill()

        rb_files = []
        if multi_output:
            rb_files = sorted(glob.glob(testout_glob))
            # zip(strict=True) keyword arg added in Python 3.10
            assert len(rb_files) == len(check_vals)
            for check_val, rb_file in zip(check_vals, rb_files):
                check_val['filename'] = rb_file

        for rbf in rb_files:
            assert os.path.isfile(rbf)

        # Output tests

        if not multi_input and not multi_output:
            # Check strict bit-for-bit passthrough.
            in_hash = hashlib.sha256()
            out_hash = hashlib.sha256()
            for in_file in in_files_l[0]:
                in_cap_file = capture_file(in_file)
                with open(in_cap_file, 'rb') as f:
                    in_hash.update(f.read())
            with open(testout_file, 'rb') as f:
                out_hash.update(f.read())
            assert in_hash.hexdigest() == out_hash.hexdigest()

        last = True
        for check_val in reversed(check_vals):
            # Iterate in reversed order; if there multiple outputs, the last
            # file is special (i.e., is guaranteed to have all the IDBs and
            # other non-packet blocks and options.)
            check_packet_count(cmd_capinfos, check_val['packet_count'], check_val['filename'])

            cap_out_info = check_capinfos_info(cmd_capinfos, check_val['filename'])
            assert check_val['packet_count'] == cap_out_info['packets']

            if multi_input and multi_output and not last:
                # Having multiple inputs forces the use of threads. In our
                # case this means that non-packet block counts in files before
                # the last is nondeterministic. We also expect any non-packet
                # blocks before the first packet block to be read in each
                # input as part of the initial pcapng_open.
                assert cap_out_info['interfaces'] >= check_val['idb_count']
            else:
                assert cap_out_info['interfaces'] == check_val['idb_count']

            if multi_input:
                # Multiple inputs, so dumpcap written SHB with its own User
                # Application option (including the version number, so check
                # a substring.)
                assert len(cap_out_info['userappl']) == 1
                assert 'Dumpcap (Wireshark)' in cap_out_info['userappl'][0]
            else:
                assert cap_out_info['userappl'] == check_val['userappl_list']

            # XXX Are there any other sanity checks we should run?
            last = False
    return check_dumpcap_pcapng_sections_real

class TestWiresharkCapture:
    def test_wireshark_capture_10_packets_to_file(self, request, wireshark_k, check_capture_10_packets, make_screenshot_on_error, test_env):
        '''Capture 10 packets from the network to a file using Wireshark'''
        disabled = request.config.getoption('--disable-gui', default=False)
        if disabled:
            pytest.skip('GUI tests are disabled via --disable-gui')
        with make_screenshot_on_error():
            check_capture_10_packets(self, cmd=wireshark_k, env=test_env)

    # Wireshark doesn't currently support writing to stdout while capturing.
    # def test_wireshark_capture_10_packets_to_stdout(self, wireshark_k, check_capture_10_packets, test_env):
    #     '''Capture 10 packets from the network to stdout using Wireshark'''
    #     check_capture_10_packets(self, cmd=wireshark_k, to_stdout=True, env=test_env)

    def test_wireshark_capture_from_fifo(self, request, wireshark_k, check_capture_fifo, make_screenshot_on_error, test_env):
        '''Capture from a fifo using Wireshark'''
        disabled = request.config.getoption('--disable-gui', default=False)
        if disabled:
            pytest.skip('GUI tests are disabled via --disable-gui')
        with make_screenshot_on_error():
            check_capture_fifo(self, cmd=wireshark_k, env=test_env)

    def test_wireshark_capture_from_stdin(self, request, wireshark_k, check_capture_stdin, make_screenshot_on_error, test_env):
        '''Capture from stdin using Wireshark'''
        disabled = request.config.getoption('--disable-gui', default=False)
        if disabled:
            pytest.skip('GUI tests are disabled via --disable-gui')
        with make_screenshot_on_error():
            check_capture_stdin(self, cmd=wireshark_k, env=test_env)

    def test_wireshark_capture_snapshot_len(self, request, wireshark_k, check_capture_snapshot_len, make_screenshot_on_error, test_env):
        '''Capture truncated packets using Wireshark'''
        disabled = request.config.getoption('--disable-gui', default=False)
        if disabled:
            pytest.skip('GUI tests are disabled via --disable-gui')
        with make_screenshot_on_error():
            check_capture_snapshot_len(self, cmd=wireshark_k, env=test_env)


class TestTsharkCapture:
    def test_tshark_capture_10_packets_to_file(self, cmd_tshark, check_capture_10_packets, test_env):
        '''Capture 10 packets from the network to a file using TShark'''
        check_capture_10_packets(self, cmd=cmd_tshark, env=test_env)

    def test_tshark_capture_10_packets_to_stdout(self, cmd_tshark, check_capture_10_packets, test_env):
        '''Capture 10 packets from the network to stdout using TShark'''
        check_capture_10_packets(self, cmd=cmd_tshark, to_stdout=True, env=test_env)

    def test_tshark_capture_from_fifo(self, cmd_tshark, check_capture_fifo, test_env):
        '''Capture from a fifo using TShark'''
        check_capture_fifo(self, cmd=cmd_tshark, env=test_env)

    def test_tshark_capture_from_stdin(self, cmd_tshark, check_capture_stdin, test_env):
        '''Capture from stdin using TShark'''
        check_capture_stdin(self, cmd=cmd_tshark, env=test_env)

    def test_tshark_capture_snapshot_len(self, cmd_tshark, check_capture_snapshot_len, test_env):
        '''Capture truncated packets using TShark'''
        check_capture_snapshot_len(self, cmd=cmd_tshark, env=test_env)


class TestDumpcapCapture:
    def test_dumpcap_capture_10_packets_to_file(self, cmd_dumpcap, check_capture_10_packets, base_env):
        '''Capture 10 packets from the network to a file using Dumpcap'''
        check_capture_10_packets(self, cmd=cmd_dumpcap, env=base_env)

    def test_dumpcap_capture_10_packets_to_stdout(self, cmd_dumpcap, check_capture_10_packets, base_env):
        '''Capture 10 packets from the network to stdout using Dumpcap'''
        check_capture_10_packets(self, cmd=cmd_dumpcap, to_stdout=True, env=base_env)

    def test_dumpcap_capture_from_fifo(self, cmd_dumpcap, check_capture_fifo, base_env):
        '''Capture from a fifo using Dumpcap'''
        check_capture_fifo(self, cmd=cmd_dumpcap, env=base_env)

    def test_dumpcap_capture_from_stdin(self, cmd_dumpcap, check_capture_stdin, base_env):
        '''Capture from stdin using Dumpcap'''
        check_capture_stdin(self, cmd=cmd_dumpcap, env=base_env)

    def test_dumpcap_capture_snapshot_len(self, check_capture_snapshot_len, cmd_dumpcap, base_env):
        '''Capture truncated packets using Dumpcap'''
        check_capture_snapshot_len(self, cmd=cmd_dumpcap, env=base_env)


class TestDumpcapAutostop:
    # duration, filesize, packets, files
    def test_dumpcap_autostop_filesize(self, check_dumpcap_autostop_stdin, base_env):
        '''Capture from stdin using Dumpcap until we reach a file size limit'''
        check_dumpcap_autostop_stdin(self, filesize=15, env=base_env)

    def test_dumpcap_autostop_packets(self, check_dumpcap_autostop_stdin, base_env):
        '''Capture from stdin using Dumpcap until we reach a packet limit'''
        check_dumpcap_autostop_stdin(self, packets=97, env=base_env) # Last prime before 100. Arbitrary.


class TestDumpcapRingbuffer:
    # duration, interval, filesize, packets, files
    def test_dumpcap_ringbuffer_filesize(self, check_dumpcap_ringbuffer_stdin, base_env):
        '''Capture from stdin using Dumpcap and write multiple files until we reach a file size limit'''
        check_dumpcap_ringbuffer_stdin(self, filesize=15, env=base_env)

    def test_dumpcap_ringbuffer_packets(self, check_dumpcap_ringbuffer_stdin, base_env):
        '''Capture from stdin using Dumpcap and write multiple files until we reach a packet limit'''
        check_dumpcap_ringbuffer_stdin(self, packets=47, env=base_env) # Last prime before 50. Arbitrary.


class TestDumpcapPcapngSections:
    def test_dumpcap_pcapng_single_in_single_out(self, check_dumpcap_pcapng_sections, base_env):
        '''Capture from a single pcapng source using Dumpcap and write a single file'''
        check_dumpcap_pcapng_sections(self, env=base_env)

    def test_dumpcap_pcapng_single_in_multi_out(self, check_dumpcap_pcapng_sections, base_env):
        '''Capture from a single pcapng source using Dumpcap and write two files'''
        check_dumpcap_pcapng_sections(self, multi_output=True, env=base_env)

    def test_dumpcap_pcapng_multi_in_single_out(self, check_dumpcap_pcapng_sections, base_env):
        '''Capture from two pcapng sources using Dumpcap and write a single file'''
        if sys.byteorder == 'big':
            pytest.skip('this test is supported on little endian only')
        check_dumpcap_pcapng_sections(self, multi_input=True, env=base_env)

    def test_dumpcap_pcapng_multi_in_multi_out(self, check_dumpcap_pcapng_sections, base_env):
        '''Capture from two pcapng sources using Dumpcap and write two files'''
        if sys.byteorder == 'big':
            pytest.skip('this test is supported on little endian only')
        check_dumpcap_pcapng_sections(self, multi_input=True, multi_output=True, env=base_env)

class TestDumpcapPcapngMixedEndian:
    def test_dumpcap_pcapng_single_in_single_out(self, check_dumpcap_pcapng_sections, base_env):
        '''Capture from a single pcapng source using Dumpcap and write a single file'''
        check_dumpcap_pcapng_sections(self, mixed_endian=True, env=base_env)

    def test_dumpcap_pcapng_single_in_multi_out(self, check_dumpcap_pcapng_sections, base_env):
        '''Capture from a single pcapng source using Dumpcap and write two files'''
        check_dumpcap_pcapng_sections(self, multi_output=True, mixed_endian=True, env=base_env)

    def test_dumpcap_pcapng_single_in_single_out_be(self, check_dumpcap_pcapng_sections, base_env):
        '''Capture from a single pcapng source using Dumpcap and write a single file'''
        check_dumpcap_pcapng_sections(self, mixed_endian=True, be_first=True, env=base_env)

    def test_dumpcap_pcapng_single_in_multi_out_be(self, check_dumpcap_pcapng_sections, base_env):
        '''Capture from a single pcapng source using Dumpcap and write two files'''
        check_dumpcap_pcapng_sections(self, multi_output=True, mixed_endian=True, be_first=True, env=base_env)

    # dumpcap doesn't support capturing from mixed-endian pipes with multiple
    # inputs (i.e., when not just passing through the SHBs and IDBs).
    # def test_dumpcap_pcapng_multi_in_single_out(self, check_dumpcap_pcapng_sections, base_env):
    #     '''Capture from a single pcapng source using Dumpcap and write a single file'''
    #     check_dumpcap_pcapng_sections(self, multi_input=True, mixed_endian=True, env=base_env)
