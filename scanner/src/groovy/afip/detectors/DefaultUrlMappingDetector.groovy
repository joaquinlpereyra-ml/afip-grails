package afip.detectors

import afip.variables.NormalVariable
import afip.vulns.DefaultUrlMappings
import afip.vulns.Vuln
import org.apache.commons.logging.LogFactory
import org.codehaus.groovy.ast.expr.BinaryExpression
import org.codehaus.groovy.ast.expr.ClosureExpression
import org.codehaus.groovy.ast.expr.GStringExpression
import org.codehaus.groovy.ast.expr.MethodCallExpression
import org.codehaus.groovy.ast.stmt.BlockStatement
import org.codehaus.groovy.ast.stmt.ExpressionStatement

class DefaultUrlMappingDetector extends Detector{

    private static final log = LogFactory.getLog(this)

    DefaultUrlMappingDetector(){
        super(DefaultUrlMappings, [], [])
    }

    ArrayList<Vuln> detect(NormalVariable variable){
        if (!on) return []
        log.debug(["title": "starting detection", "vuln": "default url mapping"])
        if (!(variable.getNode() instanceof BinaryExpression)) { return [] }
        if (!filePath.endsWith('UrlMappings.groovy')) { return [] }
        if (variable.getName() != 'mappings') { return [] }
        BinaryExpression expression = variable.getNode() as BinaryExpression
        if (!(expression.getRightExpression() instanceof ClosureExpression)) { return [] }

        ClosureExpression closure = expression.getRightExpression() as ClosureExpression
        if (!closure.getCode() instanceof BlockStatement) { return [] }
        BlockStatement block = closure.getCode() as BlockStatement
        ArrayList<ExpressionStatement> statements = block.getStatements()
        for (ExpressionStatement statement : statements) {
            if (!(statement.getExpression() instanceof MethodCallExpression)) { continue }
            MethodCallExpression methodCall = statement.getExpression() as MethodCallExpression
            if (methodCall.getMethod() instanceof GStringExpression && methodCall.getText().contains("/\$controller/\$action?/\$id?")) {
                return [new DefaultUrlMappings(filePath, expression.getLineNumber(), expression.getText())]
            }
        }
        return []
    }
}
