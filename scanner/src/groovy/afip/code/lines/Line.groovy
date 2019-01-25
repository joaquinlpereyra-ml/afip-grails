package afip.code.lines

import info.debatty.java.stringsimilarity.NormalizedLevenshtein

class Line {
    private int lineNumber
    protected String codeLine
    protected NormalizedLevenshtein stringSimilarity

    Line(String line, Integer number, List<String> code){
        stringSimilarity = new NormalizedLevenshtein()
        codeLine = line
        lineNumber = approximateLineNumber(line, number, code)
    }

    int getLineNumber(){
        return lineNumber
    }

    /**
     * Will set the line number of the line to the line number of the most
     * similar line passed on the list of code lines.
     * @param codeLines: full code divided in lines, without indentation
     */

    private Integer approximateLineNumber(String line, Integer number, List<String> codeLines){
        HashMap<Integer, Double> lineDistances = new HashMap<>()
        codeLines.eachWithIndex { l, i ->
            lineDistances.put(i, stringSimilarity.distance(l, line))
        }
        // Greatly prefer lines next to the line given by the AST
        if (lineDistances[number] < 0.50) {
            return number
        } else if (lineDistances.get(number+1) && lineDistances.get(number+1) < 0.45) {
            return number+1
        } else if (lineDistances.get(number-1) && lineDistances.get(number-1) < 0.45 ) {
            return number-1
        }

        // Widen the search a bit
        Integer closeAndSimilar = lineDistances.subMap(number-10..number+10).min { it.value }.key
        if (closeAndSimilar < 0.40) {
            return closeAndSimilar
        }

        // fuck it, search the whole file and hope for the best, lets just try to keep it sane though
        Integer minimalDistance = lineDistances.min { it.value }.key
        if (minimalDistance < 0.35) {
            return minimalDistance
        }
        // ok whatever, just return whatever the ast gave
        return number
    }
}

class CleanerLine extends Line {
    CleanerLine(String line, int number, ArrayList<String> code) {
        super(line, number, code)
    }
}

class TaintedLine extends Line {
    TaintedLine(String line, int number, ArrayList<String> code) {
        super(line, number, code)
    }
}

class VulnerableLine extends Line {
    VulnerableLine(String line, int number, ArrayList<String> code) {
        super(line, number, code)
    }
}