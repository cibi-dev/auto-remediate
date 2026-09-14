import re

class SubprocessFixer:
    @staticmethod
    def fix_shell_true(code: str) -> str:
        pattern = r"subprocess\.(run|Popen|call)\((.*?),\s*shell=True(.*?)\)"
        # Safe replacement removing shell=True
        return re.sub(pattern, r"subprocess.\g<1>(\g<2>\g<3>)", code)
