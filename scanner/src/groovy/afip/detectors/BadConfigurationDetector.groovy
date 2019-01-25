package afip.detectors

import afip.utils.Ask
import afip.variables.CollectionVariable
import afip.variables.NormalVariable
import afip.visitors.BasicVisitor
import afip.vulns.BadConfigVuln
import org.apache.commons.logging.LogFactory
import org.codehaus.groovy.ast.ASTNode
import org.codehaus.groovy.ast.expr.BinaryExpression
import org.codehaus.groovy.ast.expr.ClosureExpression
import org.codehaus.groovy.ast.expr.Expression
import org.codehaus.groovy.ast.expr.PropertyExpression

class BadConfigurationDetector extends Detector {

    /* If you wish to register a new vulnerable config,
    do the following:
    1 - Create a public boolean field with a descriptive name
    2 - add to the configToField collection an entry with the key being the config name and the value the field you set on step 1
    3 - add to the correctConfig collection an entry with the config name as the key and the correct value of the config as value
    You're done.
    */
    Map<String, String> configToField = [
            'grails.views.default.codec': 'vulnerableToXss',
            'expression': 'vulnerableToXss',
            'scriptlet': 'vulnerableToXss',
    ]
    Map<String, String> correctConfigs = [
            'grails.views.default.codec': 'html',
            'expression': 'html',
            'scriptlet': 'html',
    ]

    private static final log = LogFactory.getLog(this)
    public boolean vulnerableToXss = false
    ArrayList<File> viewFiles

    BadConfigurationDetector() {
        super(BadConfigVuln, [], [])
    }

    void setViewFiles(ArrayList<File> viewFiles) {
        this.viewFiles = viewFiles
    }

    /**
     * Will search for the binary expression in the closure expression
     * given as codecsNode with its left hand side text being equal to the codec string.
     * @param codec
     * @param codecsNode
     * @return the binary expression which left side's text equals the codec string, or null if not found.
     */
    BinaryExpression findCodec(String codec, ClosureExpression codecsNode) {
        BasicVisitor codecExtractor = new BasicVisitor() {
            public BinaryExpression codecNode
            @Override
            void visitBinaryExpression(BinaryExpression binaryExpression) {
                if (binaryExpression.getLeftExpression().getText() == codec) {
                    codecNode = binaryExpression
                } else {
                    super.visitBinaryExpression(binaryExpression)
                }
            }
        }
        codecExtractor.visitClosureExpression(codecsNode)
        return codecExtractor.codecNode
    }

    ArrayList<BadConfigVuln> detect(CollectionVariable variable) {
        if (!on) return []
        log.debug(["title": "starting detection", "vuln": "bad configuration","variableType":"variable"])
        if (variable.getName() != 'codecs') return []
        if (!filePath.endsWith('Config.groovy')) return []
        ASTNode expression = variable.getEntry("0")?.getVariable()?.getValue()
        if (!expression || !(expression instanceof ClosureExpression)) return []
        ['expression', 'scriptlet'].
                collect { k -> findCodec(k, expression)}.
                findAll { it?.getRightExpression()?.getText() != 'html' }.
                collect { new BadConfigVuln(filePath, it.getLineNumber(), it.getText()) }
    }

    /**
     * visit the binary expression, using the correctConfigs collection to search for mismatching value between the collection
     * and the actual configuration; and the configToField collection to set the right field to true in case any problem
     * has been found.
     */
    ArrayList<BadConfigVuln> detect(NormalVariable variable) {
        if (!on) return []
        log.debug(["title": "starting detection", "vuln": "bad configuration","variableType":"normalVariable"])
        ArrayList<BadConfigVuln> badConfigVuln = new ArrayList<>()
        Expression expression = variable.getNode()
        if (! (expression instanceof BinaryExpression || expression instanceof PropertyExpression )) { return [] }
        if (expression instanceof BinaryExpression && Ask.isSettingProperty(expression)) {
            def leftSide = expression.getLeftExpression()
            def rightSide = expression.getRightExpression()
            if (correctConfigs.containsKey(leftSide.getText()) && correctConfigs[leftSide.getText()] != rightSide.getText()) {
                vulnerableToXss = true
                BadConfigVuln vuln = new BadConfigVuln(filePath, expression.getLineNumber(), expression.getText())
                badConfigVuln.add(vuln)
            }
        }
        return badConfigVuln
    }
}
