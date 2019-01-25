import requests
import code
import json
import os.path
from pathlib import Path

AFIP_GROOVY_PATH = '{}/scanner'.format(Path('.'))

class Problem:
    def __init__(self, name, problem_dict):
        self.name = name
        for key in problem_dict:
            setattr(self, key, problem_dict[key])

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.__str__()

    def __getattr__(self, attr):
        print('[!] WARNING: {} not set in vuln JSON!'.format(attr))
        return ""

    def _to_camel_case(self, snake_str, capitalize_first=False):
        components = snake_str.split('_')
        first = components[0] if not capitalize_first else components[0][0].upper() + components[0][1:]
        return first + "".join(x.title() for x in components[1:])

    def _to_title_case(self, snake_str):
        return ' '.join([word[0].upper() + word[1:] for word in snake_str.split('_')])

    def register(self):
        create_groovy_files = input('Do you want to create the groovy files for this problem? [Y/n]').lower()
        if create_groovy_files == 'n':
            return
        print('[+] Creating detector file')
        self.create_detector_file()
        print('[+] Creating vuln file')
        self.create_groovy_vuln_file()
        print('[+] Creating test file')
        self.create_groovy_test_file()
        danger = input('Do you want to add to the Groovy\'s vuln list? This IS dangerous. Be sure to be on git. [Y/n]').lower()
        if danger != 'n':
            print('[+] Adding to the vuln list')
            self.add_to_groovy_vulns()
        danger = input('Do you want to add to the Groovy\'s detector list? This IS dangerous. Be sure to git. [Y/n]')
        if danger != 'n':
            print('[+] Adding to detector list')
            self.add_to_groovy_detectors()
        print('[:)] Finished')
        print('[!] You may want to add your detector to the setDetectorsFromStrings method in afip.main!')

    def create_groovy_test_file(self):
        camel_case_name = self._to_camel_case(self.name, True)
        tests_path = '{}/src/tests'.format(AFIP_GROOVY_PATH)
        file_path = '{}/{}Tests.groovy'.format(tests_path, camel_case_name)
        if os.path.isfile(file_path):
            print('[+] Test file already exists. Skipping.')
            return False
        lines = ['import afip.detectors.{}Detector'.format(camel_case_name),
                 '',
                 'class {}Tests extends BaseIntegrationTest {{'.format(camel_case_name),
                 '    def setupSpec() {',
                 '        detectorManager.addDetector(new {}Detector())'.format(camel_case_name),
                 '     }',
                 '}',
                 ]
        with open(file_path, 'w+') as f:
            f.write("\n".join(lines))
        return True

    def create_groovy_vuln_file(self):
        camel_case_name = self._to_camel_case(self.name, True)
        vulns_path = '{}/src/groovy/afip/vulns'.format(AFIP_GROOVY_PATH)
        file_path = '{}/{}.groovy'.format(vulns_path, camel_case_name)

        if os.path.isfile(file_path):
            print('[+] Vuln file already exists. Skipping.')
            return False

        java_boolean = 'true' if self.is_vuln else 'false'
        lines = ['package afip.vulns',
                 '',
                 'class {} extends Vuln {{'.format(camel_case_name),
                 '',
                 '    {}(String filePath, int lineNumber, String code) {{'.format(camel_case_name),
                 '        super(filePath, lineNumber, code)',
                 '        setFriendlyName("{}")'.format(self._to_title_case(self.name)),
                 '        setConfidence("{}")'.format(self.confidence),
                 '        setInformation("{}")'.format(self.information),
                 '        setIsVuln({})'.format(java_boolean),
                 '        setCriticality("{}")'.format(self.severity),
                 '    }',
                 '}',
                 ]
        with open(file_path, 'w+') as f:
            f.write("\n".join(lines))
        return True

    def _change_line(self, original_line, added_list_content):
        leading_spaces = len(original_line) - len(original_line.lstrip())
        line = original_line.strip()
        splited = line.split('[')
        groovy_list_contents_str = '{}'.format(splited[1][:-1])
        groovy_new_list_contents_str = '{}, {}'.format(
            groovy_list_contents_str,
            added_list_content)
        groovy_new_line = '{}{}[{}]\n'.format(
            ' '*leading_spaces,
            splited[0],
            groovy_new_list_contents_str)
        return groovy_new_line

    def _new_groovy_vuln_list(self, line, new_vuln):
        assert line.strip().startswith('private static final List<Class<Vuln>> vulnClasses = ')
        return self._change_line(line, new_vuln)

    def add_to_groovy_vulns(self):
        def is_correct_line(line):
            start = 'private static final List<Class<Vuln>> vulnClasses ='
            return line.strip().startswith(start)

        camel_case_name = self._to_camel_case(self.name, True)
        vulns_path = '{}/src/groovy/afip/vulns'.format(AFIP_GROOVY_PATH)
        file_path = '{}/Vuln.groovy'.format(vulns_path)
        with open(file_path, 'r') as f:
            original_file_lines = f.readlines()
        with open(file_path, 'w') as f:
            for line in original_file_lines:
                if is_correct_line(line) and camel_case_name not in line:
                    new_lst = self._new_groovy_vuln_list(line, camel_case_name)
                    print('[+] Replacing line. Old vs new: \n {} \n {}'.format(line, new_lst))
                    f.write(new_lst)
                else:
                    f.write(line)
        return True

    def create_detector_file(self):
        camel_case_name = self._to_camel_case(self.name, True)
        detectors_path = '{}/src/groovy/afip/detectors'.format(AFIP_GROOVY_PATH)
        file_path = '{}/{}Detector.groovy'.format(detectors_path, camel_case_name)
        if os.path.isfile(file_path):
            print('[+] Detector file already exists. Skipping.')
            return False
        lines = ['package afip.detectors',
                 ''
                 'import afip.vulns.{}'.format(camel_case_name),
                 'import afip.variables.Variable',
                 'import org.apache.commons.logging.LogFactory',
                 '',
                 'class {}Detector extends Detector {{'.format(camel_case_name),
                 '    private static final log = LogFactory.getLog(this)',
                 '',
                 '    {}Detector() {{'.format(camel_case_name),
                 '        super({}, [], [])'.format(camel_case_name),
                 '    }',
                 '',
                 '    /** Edit this method to begin. Logic to detect vulns should be here and in similar methods. */',
                 '    ArrayList<{}> detect(Variable _) {{ return [] }}'.format(camel_case_name),
                 '}',
                 ]
        with open(file_path, 'w+') as f:
            f.write("\n".join(lines))
        return True

    def add_to_groovy_detectors(self):
        camel_case_name = self._to_camel_case(self.name, True)
        managers_path = '{}/src/groovy/afip/managers'.format(AFIP_GROOVY_PATH)
        file_path = '{}/DetectorManager.groovy'.format(managers_path)

        def is_correct_line(line):
            return line.strip().startswith('private List<Class<Detector>> allDetectors = [')

        with open(file_path, 'r') as f:
            original_file_lines = f.readlines()
        with open(file_path, 'w') as f:
            for line in original_file_lines:
                if is_correct_line(line) and camel_case_name not in line:
                    new_lst = self._change_line(line, '{}Detector'.format(camel_case_name))
                    print('[+] Replacing line. Old vs new: \n {} \n {}'.format(line, new_lst))
                    f.write(new_lst)
                else:
                    f.write(line)
        return True

def load_problems():
    with open('vulns.json', 'r') as f:
        problems = json.loads(f.read())
    return problems

def pretty_print_as_supermarket_list(title, *strings):
    """Print a title (for no title, give a falsey value on first param)
    and an arbitrary number of strings like it was a nice supermarket list.
    """
    if title and strings:
        print('[{0}]'.format(title))

    for index, string in enumerate(strings, start=1):
        print('{0}.\t{1}'.format(index, string))

def get_all_problems():
    return [Problem(name, problem) for name, problem in load_problems().items()]

def deal_with_problem():
    pretty_print_as_supermarket_list('Problems', *[p.name for p in PROBLEMS])
    try:
        n = int(input('Enter the problem number you want to deal with: '))
    except ValueError:
        return False
    try:
        problem = PROBLEMS[n-1]
    except IndexError:
        print('[!] Problem does not exist')
        return True
    problem.register()
    return True

def main():
    print('[!] Your AFIP Groovy path is {}'.format(AFIP_GROOVY_PATH))
    print('Entering indivual problem handling mode. Just input nothing to go to interactive mode. Call main() to re enter.')
    input_exists = deal_with_problem()
    if not input_exists:
        code.interact(local=dict(globals()))
    keep_going = input('Do you wish to continue? [y/N] ').lower() == 'y'
    while keep_going:
        deal_with_problem()
        keep_going = input('Do you wish to continue? [y/N] ').lower() == 'y'

PROBLEMS = get_all_problems()
main()
