"""LSASS skill 本地共享原语 —— recipe.py 与 signature.py 共用一份,低层判定不漂。

★全是【通用】Windows 语义,不含任何厂商/产品名单:
- 转储库 = Windows 系统库(dbghelp/dbgcore/comsvcs)+ 未回填内存(UNKNOWN/unbacked),每台 Windows 都一样;
- 访问掩码 = Windows PROCESS_VM_READ 语义,通用。
"哪个进程读 lsass 是良性"这种【环境知识】绝不写这儿 —— 那由慢通道学成规则(见 signature.py 红线)。
"""
import re

_DUMP_LIB = re.compile(r"dbghelp|dbgcore|comsvcs|UNKNOWN|unbacked", re.I)   # 转储相关库/未回填内存(通用)
_VM_READ = 0x10                                                             # PROCESS_VM_READ


def has_dump_lib(call_trace) -> bool:
    """call_trace 是否含 Windows 转储库指纹(读内存导出凭据的通用强信号)。"""
    return bool(_DUMP_LIB.search(call_trace or ""))


def access_class(granted) -> str:
    """访问掩码类别:reads_memory(含 0x10 PROCESS_VM_READ)/ query_only / unknown。Windows 通用语义。"""
    try:
        return "reads_memory" if int(str(granted), 16) & _VM_READ else "query_only"
    except (ValueError, TypeError):
        return "unknown"


def src_key(image) -> str:
    """源进程标识:basename 小写(通用特征;具体值是环境数据,良性与否由慢通道学、不写死)。"""
    return (image or "").replace("\\", "/").split("/")[-1].strip().lower() or "?"
