import afip.main.Scanner

class PlaygroundTest extends BaseIntegrationTest{

    def "should detect dynamic cleaners"() {
        when:
            def code = """
                class Test {
                     def clean(text) { 
                        return isValidURL(text) }
                     def someController() {
                        def text = clean(params.url)
                        redirect(url: text)
                    }
                }
            """
            ArrayList<String> vuln = ['Open Redirect']
            def results = Scanner.NewSnippetScanner(code, vuln, '0').scan()
        then:
            results.get('cleaners').size() == 2
            results.get('cleaners').get(0) == 3
            results.get('cleaners').get(1) == 5
            results.get('vulnerable').isEmpty()
    }

    def "if line is both taninted and cleaned, should send both"() {
        when:
            def code = """
                    class Test {
                        def foo(){
                            def text = isValidURL(params.url)
                            redirect(url: text)
                        }
                    }
                """
            ArrayList<String> vuln = ['Open Redirect']
            HashMap<String, ArrayList<Integer>> results = Scanner.NewSnippetScanner(code, vuln, '0').scan()
        then:
            !results.get('cleaners').isEmpty()
            !results.get('tainted').isEmpty()
            results.get('cleaners').get(0) == 3
            results.get('tainted').get(0) == 3
            results.get('vulnerable').isEmpty()
    }

    def "shold see vulnerability"() {
        when:
            def code = """
                def foo() {
                    def bar = params.foo
                    if (smt) {
                        bar = isValidURL(bar)
                    }
                    redirect(url: bar)
                }
            """
            ArrayList<String> vuln = ['Open Redirect']
            HashMap<String, ArrayList<Integer>> results = Scanner.NewSnippetScanner(code, vuln, '0').scan()
        then:
            !results.get('vulnerable').isEmpty()

    }
    def "should not find taint on redirect"() {
        when:
            def code = """
                def clean(text) {
                  return isValidURL(text)
                }

                def someController() {
                  def text = params.url
                  text = clean(text)
                  redirect(url: text)
                }
            """
            ArrayList<String> vuln = ['Open Redirect']
            HashMap<String, ArrayList<Integer>> results = Scanner.NewSnippetScanner(code, vuln, '0').scan()
        then:
            results.get('tainted').size() == 1
            results.get('tainted').get(0) == 6
    }

    def "should find three cleaners"() {
        when:
            def code = """
                def clean(text) {
                    if (true) {
                      return isValidURL(text)
                    } else {
                      return isValidURL(text)
                    }
                }

                def someController() {
                  def url = clean(params.url)
                  redirect(url: url)
                } 
            """
            ArrayList<String> vuln = ['Open Redirect']
            HashMap<String, ArrayList<Integer>> results = Scanner.NewSnippetScanner(code, vuln, '0').scan()
        then:
            results.get('cleaners').size() == 2
            results.get('cleaners')[0] == 5
            results.get('cleaners')[1] == 10
            results.get('tainted').size() == 1
            results.get('tainted')[0] == 10
            results.get('vulnerable').isEmpty()

    }

    def "should return a cleaner and a tainted line for open redirect"() {
        when:
            def code = """
                    def text = params.url
                    text = isValidURL(text)
                    redirect(url: text)
                """
            ArrayList<String> vuln = ['Open Redirect']
            HashMap<String, ArrayList<Integer>> results = Scanner.NewSnippetScanner(code, vuln, '0').scan()
        then:
            results.get('cleaners').get(0) == 2
            results.get('tainted').get(0) == 1
            results.get('vulnerable').isEmpty()
    }

    def "should return a tainted and a vulnerable line for open redirect"() {
        when:
        def code = """
                def text = params.url
                redirect(url: text)
            """
        ArrayList<String> vuln = ['Open Redirect']
        HashMap<String, ArrayList<Integer>> results = Scanner.NewSnippetScanner(code, vuln, '0').scan()
        then:
        results.get('cleaners').isEmpty()
        results.get('tainted').get(0) == 1
        results.get('tainted').get(1) == 2
        results.get('vulnerable').get(0) == 2
    }

    def "should return cleaner for path traversal at line 3"() {
        when:
        def code = """
                def filePath = params.file
                def paco = new File(filePath)
                def unpaco = File.isValidPath(paco) 
                def f2 = unpaco.Read()
            """
        ArrayList<String> vuln = ['Path traversal']
        HashMap<String, ArrayList<Integer>> results = Scanner.NewSnippetScanner(code, vuln, '0').scan()
        then:
        results.get('cleaners').get(0) == 3
        results.get('tainted').get(0) == 1
        results.get('tainted').get(1) == 2
        results.get('tainted').get(2) == 3
        results.get('vulnerable').isEmpty()
    }

    def "should work fine"() {
        when:
        def code = """
                class Test {
                    def goo(){
                        def bar = params.algo
                        if (sara){
                            bar = isValidURL(bar)
                        }
                        else {
                            bar = params 
                        }
                        redirect(url: bar)
                   }
                }
            """
        ArrayList<String> vuln = ['Open Redirect']
        HashMap<String, ArrayList<Integer>> results = Scanner.NewSnippetScanner(code, vuln, '0').scan()
        then:
        !results.get('cleaners').isEmpty()
        results.get('cleaners').get(0)==5
        !results.get('tainted').isEmpty()
        results.get('tainted').get(0) == 3
        results.get('tainted').get(1) == 5
        results.get('tainted').get(2) == 8
        results.get('tainted').get(3) == 10
        !results.get('vulnerable').isEmpty()
        results.get('vulnerable').get(0) == 10
    }

    def "should return cleaner for reflected xss at line 2"() {
        when:
        def code = """
                def a = params.b
                a = a.encodedAsHTML()
                render(text: a)
            """
        ArrayList<String> vuln = ['Reflected XSS']
        HashMap<String, ArrayList<Integer>> results = Scanner.NewSnippetScanner(code, vuln, '0').scan()
        then:
        !results.get('cleaners').isEmpty()
        results.get('cleaners').get(0) == 2
        results.get('tainted').get(0) == 1
        results.get('vulnerable').isEmpty()
    }

    def "test string similarity libs"() {
        when:
        String s1 = "text = this.isValidURL(text)"
        String s2 = "text = isValidURL(text)"
        String s3 = "def unpaco = File.isValidPath(paco)"
        String s4 = " = File.isValidPath(paco)"

        info.debatty.java.stringsimilarity.NormalizedLevenshtein nleven = new info.debatty.java.stringsimilarity.NormalizedLevenshtein()

        // El valor para la distancia menor a 0.3 es a ojo, se supone que no deberia haber mayores variaciones
        then:
        nleven.distance(s1, s2) < 0.3
        nleven.distance(s3, s4) < 0.3
        nleven.distance(s1, s3) > 0.3
        nleven.distance(s1, s4) > 0.3
        nleven.distance(s2, s3) > 0.3
        nleven.distance(s2, s4) > 0.3
    }
}
