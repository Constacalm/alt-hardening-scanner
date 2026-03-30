use crate::models::{Check, Interface};

macro_rules! chk {
    (
        id: $id:expr,
        param: $param:expr,
        interface: $interface:expr,
        target: $target:expr,
        default: $default:expr,
        description: $description:expr,
        section: $section:expr $(,)?
    ) => {
        Check {
            id: $id,
            param: $param.to_string(),
            interface: $interface,
            target_value: $target.to_string(),
            default_value: $default.to_string(),
            description: $description.to_string(),
            section: $section.to_string(),
        }
    };
}

pub fn all_checks() -> Vec<Check> {
    vec![
        chk! { id: 1, param: "kernel.dmesg_restrict", interface: Interface::Sysctl, target: "1", default: "1", description: "Ограничивает доступ к сообщениям ядра.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 2, param: "kernel.kptr_restrict", interface: Interface::Sysctl, target: "2", default: "0", description: "Скрывает адреса указателей ядра.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 3, param: "init_on_alloc=1", interface: Interface::Grub, target: "present", default: "absent", description: "Инициализация выделяемой памяти нулями.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 4, param: "slab_nomerge", interface: Interface::Grub, target: "present", default: "absent", description: "Запрет слияния slab-кэшей.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 5, param: "iommu=force iommu.strict=1 iommu.passthrough=0", interface: Interface::Grub, target: "present", default: "absent", description: "Строгая конфигурация IOMMU против DMA-атак.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 6, param: "randomize_kstack_offset=1", interface: Interface::Grub, target: "present", default: "absent", description: "Рандомизация смещения стека ядра.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 7, param: "mitigations=auto,nosmt", interface: Interface::Grub, target: "present", default: "absent", description: "CPU-mitigations и ограничение SMT.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 8, param: "net.core.bpf_jit_harden", interface: Interface::Sysctl, target: "2", default: "0", description: "Усиливает защиту BPF JIT.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 9, param: "vsyscall=none", interface: Interface::Grub, target: "present", default: "absent", description: "Отключает legacy vsyscall ABI.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 10, param: "kernel.perf_event_paranoid", interface: Interface::Sysctl, target: "3", default: "4", description: "Ограничивает perf events.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 11, param: "debugfs=no-mount", interface: Interface::Grub, target: "present", default: "absent", description: "Запрещает монтирование debugfs.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 12, param: "kernel.kexec_load_disabled", interface: Interface::Sysctl, target: "1", default: "0", description: "Запрещает загрузку ядра через kexec.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 13, param: "user.max_user_namespaces", interface: Interface::Sysctl, target: "0", default: "5098941", description: "Отключает user namespaces.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 14, param: "kernel.unprivileged_bpf_disabled", interface: Interface::Sysctl, target: "1", default: "2", description: "Запрещает BPF без root.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 15, param: "vm.unprivileged_userfaultfd", interface: Interface::Sysctl, target: "0", default: "1", description: "Запрещает unprivileged userfaultfd.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 16, param: "dev.tty.ldisc_autoload", interface: Interface::Sysctl, target: "0", default: "1", description: "Запрещает автозагрузку TTY line discipline.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 17, param: "tsx=off", interface: Interface::Grub, target: "present", default: "absent", description: "Отключает Intel TSX при наличии поддержки.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 18, param: "vm.mmap_min_addr", interface: Interface::Sysctl, target: "4096", default: "65536", description: "Безопасный минимальный адрес mmap.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 19, param: "kernel.randomize_va_space", interface: Interface::Sysctl, target: "2", default: "2", description: "Поддерживает ASLR уровня 2.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 20, param: "kernel.yama.ptrace_scope", interface: Interface::Sysctl, target: "3", default: "1", description: "Полностью ограничивает ptrace.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 21, param: "fs.protected_symlinks", interface: Interface::Sysctl, target: "1", default: "1", description: "Защита символических ссылок.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 22, param: "fs.protected_hardlinks", interface: Interface::Sysctl, target: "1", default: "1", description: "Защита жёстких ссылок.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 23, param: "fs.protected_fifos", interface: Interface::Sysctl, target: "2", default: "1", description: "Усиленная защита FIFO.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 24, param: "fs.protected_regular", interface: Interface::Sysctl, target: "2", default: "1", description: "Усиленная защита обычных файлов.", section: "РД ФСТЭК, Таблица 2" },
        chk! { id: 25, param: "fs.suid_dumpable", interface: Interface::Sysctl, target: "0", default: "0", description: "Запрещает core dumps для SUID/SGID.", section: "РД ФСТЭК, Таблица 2" },
    ]
}
