import io
from lib2to3.pytree import Base
import pathlib
import logging
import typing
import sys
import os
import contextlib
import concurrent.futures
import traceback
import argparse

import elftools.elf.elffile
import elftools.construct.lib


# It seems that in python type variables used in return types must be covariant
# if they're not used as input parameters or invariant if they're used as both
# inputs and returns.
_T_co = typing.TypeVar("_T_co", covariant=True)


_logger: logging.Logger = logging.getLogger(__name__)
_logger.addHandler(logging.StreamHandler(stream=sys.stderr))


@typing.runtime_checkable
class future_like(typing.Protocol[_T_co]):

    def result(self, timeout: typing.Optional[int] = None) -> _T_co:
        ...
    
    def exception(self, timeout: typing.Optional[int] = None) -> typing.Optional[BaseException]:
        ...


def _to_loglevel(lvlstr: str) -> int:
	lvlstr_lower: str = lvlstr.lower()
	if lvlstr_lower == "critical":
		return logging.CRITICAL
	if lvlstr_lower == "error":
		return logging.ERROR
	if lvlstr_lower == "warning":
		return logging.WARNING
	if lvlstr_lower == "info":
		return logging.INFO
	if lvlstr_lower == "debug":
		return logging.DEBUG
	raise TypeError(f"Unknown log level string: {lvlstr}")


# Or we can define `__class_getitem__` in the class definition without inherting
# `typing.Generic[_T_co]`
class inplace_future(typing.Generic[_T_co]):

    def __init__(self, callable: typing.Callable[[], _T_co]) -> None:
        self._has_error: bool = False
        maybe_result_err: typing.Optional[_T_co | BaseException] = None
        try:
            maybe_result_err = callable()
        except BaseException as e:
            tb: list[str] = traceback.format_exception(type(e), e, e.__traceback__)
            maybe_result_err = e
            maybe_result_err.__cause__ = Exception('\n"""\n{}"""'.format(''.join(tb)))
            self._has_error = True
        assert maybe_result_err is not None
        self._result_err: _T_co | BaseException = typing.cast(_T_co | BaseException, maybe_result_err)
    
    def result(self, timeout: typing.Optional[int] = None) -> _T_co:
        if self._has_error:
            current_exception: BaseException = typing.cast(BaseException, self._result_err)
            raise current_exception
        
        current_result: _T_co = typing.cast(_T_co, self._result_err)
        return current_result
    
    def exception(self, timeout: typing.Optional[int] = None) -> typing.Optional[BaseException]:
        if not self._has_error:
            return None
        
        current_exception: BaseException = typing.cast(BaseException, self._result_err)
        return current_exception


class wrapped_logger:

    def __init__(self, logger_facade: logging.Logger, warp_str: str) -> None:
        self._m_logger_facade: logging.Logger = logger_facade
        self._m_warp_str: str = warp_str
    
    def debug(self, msg: str, *, exc_info: typing.Any = None, stack_info: typing.Any = None, stacklevel: int = 1) -> None:
        self._m_logger_facade.debug(self._m_warp_str.format(msg=msg), exc_info=exc_info, stack_info=stack_info, stacklevel=stacklevel)
    
    def info(self, msg: str, *, exc_info: typing.Any = None, stack_info: typing.Any = None, stacklevel: int = 1) -> None:
        self._m_logger_facade.info(self._m_warp_str.format(msg=msg), exc_info=exc_info, stack_info=stack_info, stacklevel=stacklevel)
    
    def warning(self, msg: str, *, exc_info: typing.Any = None, stack_info: typing.Any = None, stacklevel: int = 1) -> None:
        self._m_logger_facade.warning(self._m_warp_str.format(msg=msg), exc_info=exc_info, stack_info=stack_info, stacklevel=stacklevel)
    
    def error(self, msg: str, *, exc_info: typing.Any = None, stack_info: typing.Any = None, stacklevel: int = 1) -> None:
        self._m_logger_facade.error(self._m_warp_str.format(msg=msg), exc_info=exc_info, stack_info=stack_info, stacklevel=stacklevel)
    
    def critical(self, msg: str, *, exc_info: typing.Any = None, stack_info: typing.Any = None, stacklevel: int = 1) -> None:
        self._m_logger_facade.critical(self._m_warp_str.format(msg=msg), exc_info=exc_info, stack_info=stack_info, stacklevel=stacklevel)
    
    def log(self, level: int, msg: str, *, exc_info: typing.Any = None, stack_info: typing.Any = None, stacklevel: int = 1) -> None:
        self._m_logger_facade.log(level, self._m_warp_str.format(msg=msg), exc_info=exc_info, stack_info=stack_info, stacklevel=stacklevel)
    
    @property
    def logger_facade(self) -> logging.Logger:
        return self._m_logger_facade


# workaround for pyright incorrectly having return type deduced as `NoReturn`
def _elf_header_size(elf_file: elftools.elf.elffile.ELFFile) -> int:
    return elf_file.structs.Elf_Phdr.sizeof()


def _do_patch(input_stream: io.BufferedReader, logger: wrapped_logger, target_p_align: int = 0x1000) -> typing.Optional[bytearray]:
    #import pdb; pdb.set_trace()
    logger.info("Staring patching...")

    bdata: bytearray = bytearray(input_stream.read())
    updated: bool = False

    elf_file: elftools.elf.elffile.ELFFile = elftools.elf.elffile.ELFFile(input_stream)
    header_size: int = _elf_header_size(elf_file)
    for idx in range(0, elf_file.num_segments()):
        header: elftools.construct.lib.Container = elf_file.get_segment(idx).header
        maybe_p_type: typing.Optional[str] = header.get("p_type")
        if maybe_p_type is None:
            continue
        assert maybe_p_type is not None
        p_type: str = maybe_p_type
        maybe_p_align: typing.Optional[int] = header.get("p_align")
        if maybe_p_align is None:
            continue
        assert maybe_p_align is not None
        p_align: int = maybe_p_align

        if p_type == "PT_LOAD" and p_align != target_p_align:
            logger.info(f"Changing alignment of program header {idx} from {p_align} to {target_p_align}")

            header["p_align"] = target_p_align
            header_offset: int = elf_file._segment_offset(idx)
            bdata[header_offset : header_offset + header_size] = elf_file.structs.Elf_Phdr.build(header)
            updated = True
    
    return bdata if updated else None


def _patch(input_path: pathlib.Path) -> int:
    if not input_path.exists():
        raise FileNotFoundError(f"Requested target file {input_path} does not exist.")
    if not os.access(input_path, os.R_OK):
        raise PermissionError(f"Missing read permission for target file {input_path}")
    if not os.access(input_path, os.W_OK):
        raise PermissionError(f"Missing write permission for target file {input_path}.")
    
    with contextlib.ExitStack() as estack:
        _logger.info(f"Start patching file {input_path}...")
        estack.callback(lambda : _logger.info(f"Finish patching file ${input_path}"))

        wrap_logger: wrapped_logger = wrapped_logger(_logger, "Patching file %s: {msg}" % (input_path, ))

        maybe_result_data: typing.Optional[bytearray] = None
        with open(input_path, "rb") as f:
            maybe_result_data = _do_patch(f, wrap_logger)
        if maybe_result_data is None:
            _logger.warning(f"Requested target file {input_path} doesn't seem to need any patch work.")
            return 1
        assert maybe_result_data is not None
        result_data: bytearray = maybe_result_data

        with open(input_path, "wb") as f:
            f.write(result_data)
    
    return 0


class _patch_call_closure:

    def __init__(self, input_path: pathlib.Path) -> None:
        self._input_path: pathlib.Path = input_path
    
    def __call__(self) -> int:
        return _patch(self._input_path)


def _run_patch_works(input_paths: list[pathlib.Path], max_workers: typing.Optional[int] = None) -> int:
    assert len(input_paths) >= 0
    if len(input_paths) == 0:
        _logger.warning(f"No file to process is provided. Skipping this execution")
        return 1
    if max_workers is not None:
        max_workers = min(len(input_paths), typing.cast(int, max_workers))
    
    run_in_current_thread: bool = False
    while True:
        if len(input_paths) == 1:
            run_in_current_thread = True
            break
        if max_workers is None:
            break
        int_max_workers: int = max_workers
        if int_max_workers == 1:
            run_in_current_thread = True
        break
    if run_in_current_thread:
        _logger.info(f"Only one worker is needed. Will process the patch jobs in the current thread.")

    with contextlib.ExitStack() as stack:
        future_list: list[future_like[int]] = []
        if run_in_current_thread:
            for idx in range(0, len(input_paths)):
                future_list.append(inplace_future(_patch_call_closure(input_paths[idx])))
        else:
            executor: concurrent.futures.ProcessPoolExecutor = stack.enter_context(concurrent.futures.ProcessPoolExecutor(max_workers=max_workers))
            for idx in range(0, len(input_paths)):
                future_list.append(executor.submit(_patch_call_closure(input_paths[idx])))
        
        return_status: int = 0
        for current_path, current_future in zip(input_paths, future_list):
            try:
                ret: int = current_future.result()
                if ret != 0:
                    _logger.warning(f"Patching job for {current_path} exited abnormally, with exit code {ret}.")
                else:
                    _logger.info(f"Patching job for {current_path} exited successfully.")
            except Exception as e:
                exc_string: str = traceback.format_exc()
                _logger.debug(exc_string)
                _logger.error(f"Patching job for {current_path} failed with {type(e)}. Error detail: {str(e)}")
                return_status = 2
                continue
        
        return return_status
    
    assert False
    return 0


def parse_args(arg_list: list[str]) -> argparse.Namespace:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(description="Patching WSL1 ELF file settings")
    parser.add_argument("--file", type=pathlib.Path, required=True, action="append", help="The ELF file to patch. Can be specified multiple times")
    parser.add_argument("--max-workers", type=int, action="store", help="Maximum number of workers to do the patch job concurrently. Default to $(nproc), or 1 if only one file to patch.")
    parser.add_argument("--loglevel", type=_to_loglevel, action="store", help="Specifies the log level for the program logger.")

    args: argparse.Namespace = parser.parse_args(arg_list)
    return args


def main(argv: list[str]) -> int:
    args: argparse.Namespace = parse_args(argv[1:])

    if args.loglevel is not None:
        _logger.setLevel(typing.cast(int, args.loglevel))
    
    max_workers: typing.Optional[int] = None
    if args.max_workers is not None:
        max_workers = typing.cast(int, args.max_workers)
    
    files: list[pathlib.Path] = typing.cast(list[pathlib.Path], args.file)
    return_status = _run_patch_works(files, max_workers=max_workers)
    return return_status


if __name__ == "__main__":
    ret = main(sys.argv)
    sys.exit(ret)