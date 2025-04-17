#!/bin/bash

# These kernel settings are not yet stable and have not been tested. Using it in any system may cause irreversible results. 


# Kernel configuration settings
cat > .config << EOF
# Basic Privacy and Security
CONFIG_SECURITY=y
CONFIG_SECURITY_NETWORK=y
CONFIG_SECURITY_NETWORK_XFRM=y
CONFIG_SECURITY_PATH=y
CONFIG_SECURITY_LOCKDOWN_LSM=y
CONFIG_DEFAULT_SECURITY="selinux,apparmor,tomoyo,yama,lockdown"
CONFIG_LSM="lockdown,yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,bpf"

# Advanced Memory Protection
CONFIG_STRICT_KERNEL_RWX=y
CONFIG_STRICT_MODULE_RWX=y
CONFIG_STACKPROTECTOR_STRONG=y
CONFIG_CC_STACKPROTECTOR_STRONG=y
CONFIG_VMAP_STACK=y
CONFIG_THREAD_INFO_IN_TASK=y
CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
CONFIG_INIT_ON_FREE_DEFAULT_ON=y
CONFIG_PAGE_TABLE_ISOLATION=y
CONFIG_RANDOMIZE_BASE=y
CONFIG_RANDOMIZE_MEMORY=y
CONFIG_RELOCATABLE=y
CONFIG_HARDENED_USERCOPY=y
CONFIG_HARDENED_USERCOPY_FALLBACK=n
CONFIG_SLAB_FREELIST_RANDOM=y
CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_SHUFFLE_PAGE_ALLOCATOR=y
CONFIG_PARALLEL_MEMORY_PRESSURE=y
CONFIG_PAGE_POISONING=y
CONFIG_PAGE_POISONING_NO_SANITY=y
CONFIG_PAGE_POISONING_ZERO=y
CONFIG_RANDOM_TRUST_CPU=n
CONFIG_RANDOM_TRUST_BOOTLOADER=n
CONFIG_GCC_PLUGIN_STACKLEAK=y
CONFIG_GCC_PLUGIN_RANDSTRUCT=y
CONFIG_GCC_PLUGIN_LATENT_ENTROPY=y
CONFIG_DEBUG_WX=y
CONFIG_SHADOW_CALL_STACK=y
CONFIG_STATIC_USERMODEHELPER=y
CONFIG_SECURITY_DMESG_RESTRICT=y
CONFIG_STATIC_USERMODEHELPER_PATH=""

# Spectre/Meltdown/CPU Security
CONFIG_RETPOLINE=y
CONFIG_X86_KERNEL_IBT=y
CONFIG_CPU_UNRET_ENTRY=y
CONFIG_CPU_SRSO=y
CONFIG_MICROCODE=y
CONFIG_MICROCODE_INTEL=y
CONFIG_MICROCODE_AMD=y
CONFIG_RETPOLINE_LFENCE=y
CONFIG_X86_UMIP=y
CONFIG_X86_INTEL_TSX_MODE_OFF=y
CONFIG_X86_MCE=y
CONFIG_X86_MCE_INTEL=y
CONFIG_X86_MCE_AMD=y
CONFIG_X86_SGX=n

# Hardware Security
CONFIG_INTEL_IOMMU=y
CONFIG_INTEL_IOMMU_DEFAULT_ON=y
CONFIG_INTEL_IOMMU_SVM=y
CONFIG_AMD_IOMMU=y
CONFIG_AMD_IOMMU_V2=y
CONFIG_IOMMU_DEFAULT_DMA_STRICT=y
CONFIG_DRM_LEGACY=n
CONFIG_FRAMEBUFFER_CONSOLE=n
CONFIG_SPEAKUP=n
CONFIG_THUNDERBOLT=n
CONFIG_INTEL_TXT=n
CONFIG_INTEL_MEI=n
CONFIG_INTEL_MEI_ME=n
CONFIG_INTEL_MEI_TXT=n
CONFIG_INTEL_MISC_COMPAT=n
CONFIG_STAGING=n

# Network Security and Privacy
CONFIG_IPV6_PRIVACY=y
CONFIG_TCP_CONG_BBR=y
CONFIG_DEFAULT_BBR=y
CONFIG_INET_DIAG=n
CONFIG_INET_TCP_DIAG=n
CONFIG_INET_UDP_DIAG=n
CONFIG_INET_RAW_DIAG=n
CONFIG_INET_DIAG_DESTROY=n
CONFIG_PACKET_DIAG=n
CONFIG_UNIX_DIAG=n
CONFIG_NETLINK_DIAG=n
CONFIG_WIRELESS=n
CONFIG_CFG80211=n
CONFIG_MAC80211=n
CONFIG_WEXT_CORE=n
CONFIG_WEXT_PROC=n
CONFIG_WEXT_SPY=n
CONFIG_WEXT_PRIV=n
CONFIG_USB_NET_DRIVERS=n
CONFIG_WLAN=n
CONFIG_NFC=n
CONFIG_BLUETOOTH=n
CONFIG_BT=n
CONFIG_RFKILL=n
CONFIG_NET_9P=n
CONFIG_CIFS=n
CONFIG_SMB_SERVER=n
CONFIG_NETWORK_FILESYSTEMS=n

# File System Security
CONFIG_EXT4_FS_ENCRYPTION=y
CONFIG_EXT4_FS_SECURITY=y
CONFIG_F2FS_FS_ENCRYPTION=y
CONFIG_FS_ENCRYPTION=y
CONFIG_FS_ENCRYPTION_INLINE_CRYPT=y
CONFIG_FS_VERITY=y
CONFIG_FS_VERITY_BUILTIN_SIGNATURES=y
CONFIG_DM_CRYPT=y
CONFIG_DM_INTEGRITY=y
CONFIG_DM_VERITY=y
CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG=y
CONFIG_DM_VERITY_FEC=y
CONFIG_ENCRYPTED_KEYS=y
CONFIG_FSNOTIFY=y
CONFIG_DNOTIFY=y
CONFIG_INOTIFY_USER=y
CONFIG_FANOTIFY=y
CONFIG_QUOTA=y
CONFIG_QUOTA_NETLINK_INTERFACE=y
CONFIG_MANDATORY_FILE_LOCKING=y
CONFIG_FS_POSIX_ACL=y
CONFIG_OVERLAY_FS_REDIRECT_DIR=y

# Cryptographic Security
CONFIG_CRYPTO=y
CONFIG_CRYPTO_FIPS=y
CONFIG_CRYPTO_MANAGER_DISABLE_TESTS=y
CONFIG_CRYPTO_SHA512=y
CONFIG_CRYPTO_SHA3=y
CONFIG_CRYPTO_CHACHA20POLY1305=y
CONFIG_CRYPTO_BLAKE2B=y
CONFIG_CRYPTO_BLAKE2S=y
CONFIG_CRYPTO_CURVE25519=y
CONFIG_CRYPTO_CURVE25519_X86_64=y
CONFIG_CRYPTO_STREEBOG=y
CONFIG_CRYPTO_AES_NI_INTEL=y
CONFIG_CRYPTO_DRBG_MENU=y
CONFIG_CRYPTO_DRBG_HMAC=y
CONFIG_CRYPTO_DRBG_HASH=y
CONFIG_CRYPTO_DRBG_CTR=y
CONFIG_CRYPTO_JITTERENTROPY=y
CONFIG_CRYPTO_USER_API_HASH=y
CONFIG_CRYPTO_USER_API_SKCIPHER=y
CONFIG_CRYPTO_USER_API_RNG=y
CONFIG_CRYPTO_USER_API_AEAD=y

# System Call and Monitoring Protection
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
CONFIG_SECURITY_LANDLOCK=y
CONFIG_SECURITY_LOCKDOWN_LSM=y
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y
CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y
CONFIG_SECURITY_YAMA=y
CONFIG_AUDIT=n
CONFIG_AUDITSYSCALL=n
CONFIG_AUDIT_WATCH=n
CONFIG_AUDIT_TREE=n
CONFIG_AUDIT_GENERIC=n
CONFIG_COMPAT_BRK=n
CONFIG_DEVKMEM=n
CONFIG_PROC_KCORE=n
CONFIG_PROC_VMCORE=n
CONFIG_PROC_PAGE_MONITOR=n
CONFIG_USELIB=n
CONFIG_CHECKPOINT_RESTORE=n
CONFIG_USERFAULTFD=n
CONFIG_COREDUMP=n

# Debugging Disabled
CONFIG_DEBUG_INFO=n
CONFIG_DEBUG_INFO_DWARF4=n
CONFIG_DEBUG_INFO_BTF=n
CONFIG_KGDB=n
CONFIG_MAGIC_SYSRQ=n
CONFIG_DETECT_HUNG_TASK=n
CONFIG_SCHED_DEBUG=n
CONFIG_STACK_VALIDATION=n
CONFIG_UNWINDER_ORC=n
CONFIG_FTRACE=n
CONFIG_KPROBE_EVENTS=n
CONFIG_UPROBE_EVENTS=n
CONFIG_PROBE_EVENTS=n
CONFIG_RING_BUFFER_BENCHMARK=n
CONFIG_HIST_TRIGGERS=n

# Performance Optimizations
CONFIG_PREEMPT=y
CONFIG_HZ_1000=y
CONFIG_HZ=1000
CONFIG_NO_HZ=y
CONFIG_NO_HZ_FULL=y
CONFIG_RCU_FAST_NO_HZ=y
CONFIG_TASK_DELAY_ACCT=n
CONFIG_RCU_NOCB_CPU=y
CONFIG_NUMA_BALANCING=y
CONFIG_NUMA_BALANCING_DEFAULT_ENABLED=y
CONFIG_SCHED_SMT=y
CONFIG_SCHED_MC=y
CONFIG_SCHED_AUTOGROUP=y
CONFIG_CLEANCACHE=y
CONFIG_FRONTSWAP=y
CONFIG_ZSWAP=y
CONFIG_ZPOOL=y
CONFIG_ZBUD=y
CONFIG_Z3FOLD=y
CONFIG_ZSMALLOC=y
CONFIG_PGTABLE_MAPPING=y
CONFIG_TRANSPARENT_HUGEPAGE=y
CONFIG_TRANSPARENT_HUGEPAGE_ALWAYS=y
CONFIG_MEMORY_FAILURE=y
CONFIG_MEMORY_HOTPLUG=y
CONFIG_MEMORY_HOTREMOVE=y
CONFIG_KSM=y
CONFIG_DEFAULT_MMAP_MIN_ADDR=65536
CONFIG_MMAP_NOEXEC_TAINT=0

# Advanced CPU Optimizations
CONFIG_PROCESSOR_SELECT=y
CONFIG_GENERIC_CPU=n
CONFIG_MNATIVE=y
CONFIG_GENERIC_CPU_VULNERABILITIES=y
CONFIG_NUMA_AWARE_SPINLOCKS=y
CONFIG_QUEUED_SPINLOCKS=y
CONFIG_PARAVIRT_SPINLOCKS=y
CONFIG_QUEUE_RWLOCK=y
CONFIG_ARCH_CPUIDLE_HALTPOLL=y
CONFIG_HALTPOLL_CPUIDLE=y
CONFIG_CPU_IDLE_GOV_HALTPOLL=y
CONFIG_CPU_IDLE_GOV_TEO=y
CONFIG_INTEL_IDLE=y
CONFIG_AMD_IDLE=y

# Advanced Timer Settings
CONFIG_HIGH_RES_TIMERS=y
CONFIG_NO_HZ_FULL_ALL=y
CONFIG_NO_HZ_IDLE=y
CONFIG_NO_HZ=y
CONFIG_SCHED_HRTICK=y
CONFIG_TICK_CPU_ACCOUNTING=y
CONFIG_VIRT_CPU_ACCOUNTING_GEN=y
CONFIG_IRQ_TIME_ACCOUNTING=y
CONFIG_SCHED_THERMAL_PRESSURE=y

# Advanced I/O Optimizations
CONFIG_IO_URING=y
CONFIG_BLK_WBT=y
CONFIG_BLK_WBT_MQ=y
CONFIG_MQ_IOSCHED_DEADLINE=y
CONFIG_MQ_IOSCHED_KYBER=y
CONFIG_IOSCHED_BFQ=y
CONFIG_BFQ_GROUP_IOSCHED=y
CONFIG_BLK_CGROUP_IOLATENCY=y
CONFIG_BLK_CGROUP_IOCOST=y
CONFIG_BLK_CGROUP_FC_APPID=y

# Memory Management Optimizations
CONFIG_TRANSPARENT_HUGEPAGE=y
CONFIG_TRANSPARENT_HUGEPAGE_ALWAYS=y
CONFIG_MEMORY_FAILURE=y
CONFIG_MEMORY_HOTPLUG=y
CONFIG_MEMORY_HOTREMOVE=y
CONFIG_ZONE_DEVICE=y
CONFIG_DEVICE_PRIVATE=y
CONFIG_ZONE_DMA32=y
CONFIG_COMPACTION=y
CONFIG_PAGE_REPORTING=y
CONFIG_CMA=y
CONFIG_CMA_AREAS=7
CONFIG_CLEANCACHE=y
CONFIG_FRONTSWAP=y
CONFIG_ZSWAP=y
CONFIG_ZPOOL=y
CONFIG_ZBUD=y
CONFIG_Z3FOLD=y
CONFIG_ZSMALLOC=y
CONFIG_PERCPU_STATS=y

# Network Optimizations
CONFIG_NET_SCH_FQ_CODEL=y
CONFIG_NET_SCH_FQ=y
CONFIG_NET_SCH_HTB=y
CONFIG_NET_SCH_HFSC=y
CONFIG_NET_SCH_CAKE=y
CONFIG_NET_SCH_PIE=y
CONFIG_TCP_CONG_BBR=y
CONFIG_TCP_CONG_BBR2=y
CONFIG_DEFAULT_BBR2=y
CONFIG_IP_ADVANCED_ROUTER=y
CONFIG_IP_MULTIPLE_TABLES=y
CONFIG_IP_ROUTE_MULTIPATH=y
CONFIG_IP_ROUTE_VERBOSE=y
CONFIG_TCP_CONG_CUBIC=y
CONFIG_TCP_CONG_WESTWOOD=y
CONFIG_NET_RX_BUSY_POLL=y
CONFIG_NET_FLOW_LIMIT=y
CONFIG_INET_UDP_DIAG=y
CONFIG_INET_DIAG_DESTROY=y

# File System Optimizations
CONFIG_FS_DAX=y
CONFIG_FS_POSIX_ACL=y
CONFIG_FS_ENCRYPTION=y
CONFIG_FS_VERITY=y
CONFIG_OVERLAY_FS=y
CONFIG_OVERLAY_FS_REDIRECT_DIR=y
CONFIG_OVERLAY_FS_INDEX=y
CONFIG_OVERLAY_FS_XINO_AUTO=y
CONFIG_OVERLAY_FS_METACOPY=y
CONFIG_FSCACHE=y
CONFIG_CACHEFILES=y
CONFIG_BCACHE=y
CONFIG_BTRFS_FS=y
CONFIG_BTRFS_FS_POSIX_ACL=y
CONFIG_F2FS_FS=y
CONFIG_F2FS_FS_SECURITY=y
CONFIG_F2FS_FS_ENCRYPTION=y
CONFIG_F2FS_FS_COMPRESSION=y
CONFIG_XFS_FS=y
CONFIG_XFS_QUOTA=y
CONFIG_XFS_POSIX_ACL=y
CONFIG_EXT4_FS_SECURITY=y
CONFIG_EXT4_FS_ENCRYPTION=y
CONFIG_EXT4_FS_POSIX_ACL=y

# Security Optimizations (Compatibility Focused)
CONFIG_SECURITY=y
CONFIG_SECURITY_NETWORK=y
CONFIG_SECURITY_NETWORK_XFRM=y
CONFIG_SECURITY_PATH=y
CONFIG_SECURITY_YAMA=y
CONFIG_STRICT_KERNEL_RWX=y
CONFIG_STRICT_MODULE_RWX=y
CONFIG_STACKPROTECTOR_STRONG=y
CONFIG_CC_STACKPROTECTOR_STRONG=y
CONFIG_HARDENED_USERCOPY=y
CONFIG_SLAB_FREELIST_RANDOM=y
CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_SHUFFLE_PAGE_ALLOCATOR=y
CONFIG_DEFAULT_MMAP_MIN_ADDR=65536
CONFIG_SECURITY_SELINUX=y
CONFIG_SECURITY_APPARMOR=y
CONFIG_SECURITY_LANDLOCK=y
CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
CONFIG_INIT_ON_FREE_DEFAULT_ON=y

# Performance Monitoring and Debug (Limited)
CONFIG_PERF_EVENTS=y
CONFIG_PERF_EVENTS_INTEL_UNCORE=y
CONFIG_PERF_EVENTS_AMD_POWER=y
CONFIG_PERF_EVENTS_AMD_UNCORE=y
CONFIG_HAVE_PERF_EVENTS=y
CONFIG_PERF_EVENTS_INTEL_RAPL=y
CONFIG_HAVE_HARDLOCKUP_DETECTOR_PERF=y
CONFIG_HAVE_PERF_REGS=y
CONFIG_HAVE_PERF_USER_STACK_DUMP=y
CONFIG_DEBUG_FS=y
CONFIG_DYNAMIC_DEBUG=y
CONFIG_SYMBOLIC_ERRNAME=y

# Hardware Support (Basic)
CONFIG_PCI_MSI=y
CONFIG_HW_RANDOM_INTEL=y
CONFIG_HW_RANDOM_AMD=y
CONFIG_INTEL_PMC_CORE=y
CONFIG_AMD_PMC=y
CONFIG_X86_AMD_PLATFORM_DEVICE=y
CONFIG_X86_INTEL_PSTATE=y
CONFIG_X86_ACPI_CPUFREQ=y
CONFIG_CPU_FREQ_GOV_PERFORMANCE=y
CONFIG_CPU_FREQ_GOV_POWERSAVE=y
CONFIG_CPU_FREQ_GOV_USERSPACE=y
CONFIG_CPU_FREQ_GOV_ONDEMAND=y
CONFIG_CPU_FREQ_GOV_CONSERVATIVE=y
CONFIG_CPU_FREQ_GOV_SCHEDUTIL=y
CONFIG_SND_HDA_INTEL=y
CONFIG_SND_HDA_CODEC_REALTEK=y
CONFIG_SND_HDA_CODEC_HDMI=y
CONFIG_DRM_I915=y
CONFIG_DRM_AMD_DC=y
CONFIG_DRM_AMDGPU=y
CONFIG_DRM_NOUVEAU=y

# Virtualization Support
CONFIG_KVM=y
CONFIG_KVM_INTEL=y
CONFIG_KVM_AMD=y
CONFIG_VHOST_NET=y
CONFIG_VHOST_SCSI=y
CONFIG_VHOST=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_NET=y
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_CONSOLE=y
CONFIG_VIRTIO=y
EOF

# System privacy settings
cat > /etc/sysctl.d/99-privacy.conf << EOF
# Network security and performance
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_autocorking = 1
net.ipv4.tcp_no_metrics_save = 0
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = 1024
net.ipv4.tcp_min_snd_mss = 536
net.ipv4.ip_no_pmtu_disc = 0
net.ipv4.route.flush = 1
net.ipv4.tcp_congestion_control = bbr2
net.core.default_qdisc = fq
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_early_retrans = 3
net.ipv4.tcp_recovery = 1
net.ipv4.tcp_thin_linear_timeouts = 1
net.ipv4.tcp_limit_output_bytes = 262144
net.ipv4.tcp_moderate_rcvbuf = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 8192
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# IPv6 settings (secure configuration instead of disabling)
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2
net.ipv6.conf.all.addr_gen_mode = 3

# Memory and system optimizations
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16
vm.page-cluster = 0
vm.swappiness = 10
vm.dirty_background_ratio = 5
vm.dirty_ratio = 10
vm.dirty_expire_centisecs = 500
vm.dirty_writeback_centisecs = 100
vm.max_map_count = 262144
vm.mmap_min_addr = 65536
vm.overcommit_memory = 0
vm.overcommit_ratio = 50
vm.panic_on_oom = 0
vm.oom_kill_allocating_task = 1
vm.unprivileged_userfaultfd = 0
vm.vfs_cache_pressure = 50
vm.zone_reclaim_mode = 0
vm.compaction_proactiveness = 100
vm.min_free_kbytes = 65536
vm.watermark_boost_factor = 15000
vm.watermark_scale_factor = 125
vm.stat_interval = 10

# Kernel security settings (compatibility focused)
kernel.kptr_restrict = 1
kernel.dmesg_restrict = 1
kernel.printk = 3 3 3 3
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 1
kernel.kexec_load_disabled = 1
kernel.sysrq = 0
kernel.randomize_va_space = 2
kernel.perf_event_paranoid = 2
kernel.pid_max = 65536
kernel.shmmax = 268435456
kernel.shmall = 2097152
kernel.msgmax = 65536
kernel.msgmnb = 65536
kernel.sem = 250 32000 100 128

# File system settings
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.file-max = 262144
fs.aio-max-nr = 262144
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 512
fs.inotify.max_queued_events = 32768
EOF

# Module blacklisting
cat > /etc/modprobe.d/privacy-blacklist.conf << EOF
install uvcvideo /bin/false
install videobuf2_common /bin/false
install videobuf2_memops /bin/false
install videobuf2_v4l2 /bin/false
install videobuf2_vmalloc /bin/false
install videodev /bin/false
install media /bin/false
install snd_hda_codec_hdmi /bin/false
install snd_hda_intel /bin/false
install snd_hda_codec /bin/false
install snd_hwdep /bin/false
install soundcore /bin/false
install snd /bin/false
install snd_timer /bin/false
install snd_pcm /bin/false
install ac97_bus /bin/false
install i2c_piix4 /bin/false
install i2c_core /bin/false
install cdrom /bin/false
install sr_mod /bin/false
install thermal /bin/false
install battery /bin/false
install ac /bin/false
install rfkill /bin/false
install joydev /bin/false
install input_leds /bin/false
install usbhid /bin/false
install hid_generic /bin/false
install hid /bin/false
install bluetooth /bin/false
install btusb /bin/false
install uvcvideo /bin/false
install v4l2_common /bin/false
EOF

# AppArmor profiles (more compatible)
mkdir -p /etc/apparmor.d/
cat > /etc/apparmor.d/system_wide << EOF
#include <tunables/global>

profile system_wide flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/user-tmp>
  #include <abstractions/authentication>
  #include <abstractions/nameservice>
  #include <abstractions/dbus-session>
  
  # Basic system access
  /bin/** mr,
  /sbin/** mr,
  /usr/bin/** mr,
  /usr/sbin/** mr,
  /usr/local/bin/** mr,
  /usr/local/sbin/** mr,
  
  # Configuration access
  /etc/passwd r,
  /etc/group r,
  /etc/hosts r,
  
  # Temporary file access
  owner /tmp/** rw,
  owner /var/tmp/** rw,
  
  # Home directory access
  owner @{HOME}/** rw,
  owner @{HOME}/.[!.]* rw,
  
  # Network access
  network inet stream,
  network inet6 stream,
  network inet dgram,
  network inet6 dgram,
  
  # Audio and video (limited)
  /dev/snd/* rw,
  owner /dev/video* rw,
  
  # System information
  /proc/cpuinfo r,
  /proc/meminfo r,
  /proc/stat r,
  /proc/uptime r,
  /proc/version r,
  /proc/sys/kernel/hostname r,
  
  # X11 access
  /usr/share/X11/** r,
  owner /tmp/.X11-unix/* rw,
}
EOF

# PAM security settings (more compatible)
cat > /etc/security/limits.d/privacy.conf << EOF
* soft nofile 65536
* hard nofile 65536
* soft nproc 32768
* hard nproc 32768
* soft memlock 256000
* hard memlock 256000
* soft as unlimited
* hard as unlimited
EOF

# SSH security settings (more compatible)
cat > /etc/ssh/sshd_config.d/99-privacy.conf << EOF
Protocol 2
PermitRootLogin prohibit-password
MaxAuthTries 5
MaxSessions 10
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
X11Forwarding no
AllowAgentForwarding yes
AllowTcpForwarding yes
PermitTunnel no
ClientAliveInterval 300
ClientAliveCountMax 3
LoginGraceTime 60
MaxStartups 10:30:100
UseDNS no
EOF

# GRUB security settings (more compatible)
cat > /etc/default/grub.d/99-privacy.cfg << EOF
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash apparmor=1 security=apparmor lsm=landlock,lockdown,yama,apparmor,bpf audit=0 intel_iommu=on amd_iommu=on iommu=force pti=on randomize_kstack_offset=on page_alloc.shuffle=1 vsyscall=none init_on_alloc=1 init_on_free=1 slab_nomerge=n mce=0"
GRUB_CMDLINE_LINUX=""
GRUB_DISABLE_RECOVERY="true"
GRUB_TIMEOUT=5
EOF

# System services (only disable unnecessary ones)
systemctl mask apport.service
systemctl mask whoopsie.service
systemctl mask kerneloops.service
systemctl mask avahi-daemon.service
systemctl mask cups.service

# Kernel compilation
make olddefconfig
make -j$(nproc) bzImage
make -j$(nproc) modules
make modules_install
make install

echo "Balanced privacy and security settings completed." 
