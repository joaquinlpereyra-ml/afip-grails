package afip.groovy

import spock.lang.Specification

class AfipServiceTest extends Specification {

    private AfipService service

    def setup(){
        service = new AfipService()
        service.requestsService = Mock(RequestsService)
        service.requestsService.postError(_,_,_) >> { args -> args}
    }

    def "scan failed incorrect json (queue) "() {
        given:
        def json =
                ['meta':
                         ['callback': 'url'],
                 'data':
                         ['id':'scanHash',
                          'attributes':['groovy': null]
                         ]
                ]

        when:
        def result = service.startScan(json)

        then:
        result[0] == 'url'
        result[1].title == ['FailedJsonValidations']
        result[1].detail == ['[noGroovyQueue:The response must include a queue for the groovy language]']
        result[2] == 'scanHash'
    }

    def "scan failed incorrect json (no callback) "() {
        given:
        def json =
                ['meta':
                         ['callback': null],
                 'data':
                         ['id':'scanHash',
                          'attributes':['groovy':'queue']
                         ]
                ]

        when:
        def result = service.startScan(json)

        then:
        result[0] == null
        result[1].title == ['FailedJsonValidations']
        result[1].detail == ['[NoCallback:The response must provide a callback to post the results!]']
        result[2] == 'scanHash'
    }

    def "scan failed not valid repo"() {
        given:
        def queue =
                ['attributes':
                         ['repositoryURL': 'repoUrl'],
                 'id': 'hash'
                ]
        def json =
                ['meta':
                        ['callback':'url',
                         'disableTestProbe': true],
                 'data':
                         ['id':'scanHash',
                          'attributes':
                                  ['groovy': [queue]]
                         ]
                ]

        when:
        def result = service.startScan(json)

        then:
        result[0] == 'url'
        result[1].title == ['NotValidRepository']
        result[1].detail == ['Repo URL must start with "https://github.com/". Note no www involved.']
        result[2] == 'hash'
    }

    def "scan failed wrong callback"() {
        given:
        def queue =
                ['attributes':
                         ['repositoryURL': 'https://github.com/test'],
                 'id': 'hash'
                ]
        def json =
                ['meta':
                         ['callback':'url',
                          'disableTestProbe': false],
                 'data':
                         ['id':'scanHash',
                          'attributes':
                                  ['groovy': [queue]]
                         ]
                ]
        service.requestsService.testPost(_) >> false

        when:
        def result = service.startScan(json)

        then:
        result[0] == 'url'
        result[1].title == ['WrongCallback']
        result[1].detail == ['Supply a valid callback address to post to']
        result[2] == 'hash'
    }

    def "scan failed address commit"() {
        given:
        def queue =
                ['attributes':
                         ['repositoryURL': 'https://github.com/test'],
                 'id': 'hash'
                ]
        def json =
                ['meta':
                         ['callback':'url',
                          'disableTestProbe': true],
                 'data':
                         ['id':'scanHash',
                          'attributes':
                                  ['groovy': [queue]]
                         ]
                ]
        service.requestsService.commit(_,_) >> { args -> throw new Exception('commit error') }

        when:
        def result = service.startScan(json)

        then:
        result[0] == 'url'
        result[1].title == ['FailedAddressCommit']
        result[1].detail == ['commit error']
        result[2] == 'hash'
    }
}
