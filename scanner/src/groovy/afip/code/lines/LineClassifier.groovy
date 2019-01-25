package afip.code.lines

class LineClassifier {
    private String vulnScanned  = ""
    private ArrayList<String> codeLines = new ArrayList<>()
    private ArrayList<CleanerLine> cleanerLines = new ArrayList<>()
    private ArrayList<TaintedLine> taintedLines = new ArrayList<>()
    private ArrayList<VulnerableLine> vulnerableLines = new ArrayList<>()

    LineClassifier(String snippet, String vulnName){
        snippet.split("\\r?\\n").each {codeLines.add(it.replaceAll("^\\s*", "")) }
        vulnScanned = vulnName
    }

    void addCleaner(String codeline, int lineNumber){
        CleanerLine newline = new CleanerLine(codeline, lineNumber, codeLines)
        cleanerLines.add(newline)
    }

    void addTainted(String codeline, int lineNumber){
        TaintedLine newline = new TaintedLine(codeline, lineNumber, codeLines)
        taintedLines.add(newline)
    }

    void addVulnerable(String codeline, int lineNumber){
        VulnerableLine newline = new VulnerableLine(codeline, lineNumber, codeLines)
        vulnerableLines.add(newline)
    }

    HashMap<String, ArrayList<Integer>> getResult(){
        // Return a map with results ordered and without duplicates

        ArrayList<Integer> cleaners = cleanerLines.collect{ it.getLineNumber()}
        Set<Integer> c = new HashSet<>()
        c.addAll(cleaners)
        cleaners.clear()
        cleaners.addAll(c)
        Collections.sort(cleaners)

        ArrayList<Integer> taints = taintedLines.collect{ it.getLineNumber()}
        Set<Integer> t = new HashSet<>()
        t.addAll(taints)
        taints.clear()
        taints.addAll(t)
        Collections.sort(taints)


        ArrayList<Integer> vulns = vulnerableLines.collect{ it.getLineNumber()}
        Set<Integer> v = new HashSet<>()
        v.addAll(vulns)
        vulns.clear()
        vulns.addAll(v)
        Collections.sort(vulns)

        HashMap<String, ArrayList<Integer>> classifiedLines = new HashMap<>()
        classifiedLines.put("cleaners", cleaners)
        classifiedLines.put("tainted", taints)
        classifiedLines.put("vulnerable", vulns)
        return classifiedLines
    }

}
