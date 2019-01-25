import afip.vulns.PathTraversal
import afip.vulns.ReflectedXss

class CleanersTests extends BaseIntegrationTest {

        def "should not detect rxss"() {
            when:
                def code = """
                         class Test{
                            String cleaner() {
                                a = a.encodedAsHTML()                    
                            }
                            void notMethod(){
                                def b = params.danger
                                b = cleaner(b)
                                render(model: b)
                            }
                         }
                    """
            def vulns = visitAndCreateAndDetectFromClass(code)
            then:
                vulns.isEmpty()
                classScope.getMethodOfName("cleaner").isCleanerOf(ReflectedXss)
                !classScope.getMethodOfName("notMethod").isSinkOf(ReflectedXss)
        }

        def "should not detect path traversal"() {
                when:
                    def code = """
                             class Test{
                                String cleaner(String a) {
                                    a = a.getCanonicalPath()                    
                                }
                                
                                void notMethod(){
                                    def b = params.danger
                                    b = cleaner(b)
                                    def c = new File(b)
                                    c.Write()
                                }
                             }
                        """
                    def vulns = visitAndCreateAndDetectFromClass(code)
                then:
                    vulns.isEmpty()
                    classScope.getMethodOfName("cleaner").isCleanerOf(PathTraversal)
                    !classScope.getMethodOfName("notMethod").isSinkOf(PathTraversal)

        }

        def "should not add notMethod as cleaner and should not detect vuln"() {
                when:
                    def code = """
                             class Test{
                                String cleaner(String a) {
                                    a = a.getCanonicalPath()                    
                                    return a
                                }
                                void notMethod(){
                                    def b = params.danger
                                    c = cleaner(b)
                                    def d = new File(c)
                                    d.Write()
                                    c = b
                                }
                             }
                        """
                def vulns = visitAndCreateAndDetectFromClass(code)
                then:
                    vulns.isEmpty()
                    classScope.getMethodOfName("cleaner").isCleanerOf(PathTraversal)
                    !classScope.getMethodOfName("notMethod").isCleanerOf(PathTraversal)
        }

}
