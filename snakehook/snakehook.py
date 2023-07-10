import atexit
import sys

from collections import defaultdict


def register_hook(user_log: list[str]|None = None, user_suppress: list[str]|None = None) -> None:
    """
    Performs initialization of globals and registration of audit and exit events.

    This function exists to wrap _hook() in a manner that allows for worry free import,
    while also ensuring that a rational set of default arguments is accessible. This
    will not prevent the execution of malicious files. There is a high propensity
    that certain additional behavior could cause a recursion limit to be reached
    by the _hook system audit function raising its own system audits. The default 
    configuration of setup attempts to avoid this.

    We make a call to atexit to register the printing of the dictionary so in the
    event that the script terminates early due to an error, we are still able to 
    recover specified logged events. The internal method os_exit() will still 
    cause us to lose our dictionary, but this shouldn't happen in regular use.

    Args:
        user_log: A list of audit events to log to a dictionary.
        user_suppress: A list of audit events to suppress in the stdout.
    """

    # Globals because audit hooks are the dark arts.
    global suppress_list
    global log_list
    global log_dict
    log_dict = defaultdict(list)
    log_list = ['import','compile','open','listdir']
    suppress_list = ['marshal.loads', 'object.__setattr__', 'builtins.input']
    if user_log:
        log_list = user_log
    if user_suppress:
        suppress_list = user_suppress
    atexit.register(print,log_dict)
    sys.addaudithook(_hook)

def _hook(event, args):
    if event not in suppress_list:
        if event not in log_list:
            print(f'Audit event {event} detected.',
                    f'Arguments {args}', sep='\n')
        else:
            log_dict[event].append(args[0])
