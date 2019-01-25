package afip.groovy

class PollMiddlewareJob {
    def afipService
    def requestsService

    static triggers = {
      simple repeatInterval: 5000l // execute job once in 5 seconds
    }

    def execute() {
        if (afipService.isBusy()) { return }
        requestsService.getQueue({ json ->
            if (json == null) {
                return
            }
            afipService.startScan(json)
        })
    }
}
