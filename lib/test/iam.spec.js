var expect = require('chai').expect,
    iam = require('./../iam');

describe('#processIamData', function(){
    it('Processes each Resource into a Regular Expression', function(){

        var sampleIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["CanRead"],
                    "Resource": [
                        "ssrn:ss:iam:::account/100/assessmentgroup/*/customquestions"
                    ]
                }
            ]
        };

        var processedIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["CanRead"],
                    "ActionRegex": ["^CanRead$"],
                    "Resource": [
                        "ssrn:ss:iam:::account/100/assessmentgroup/*/customquestions"
                    ],
                    "ResourceRegex": [
                        "^ssrn:ss:iam:::account/100/assessmentgroup/([0-9A-Za-z_]+/?)*/customquestions$"
                    ]
                }
            ]
        };

        expect(iam.processIamData(sampleIam)).to.deep.equal(processedIam);
    });

    it('While Processing each Resource and Action into a Regular Expression Remove all Hidden Characters', function(){

        var sampleIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["*:*"],
                    "Resource": [
                        "ssrn:ss:sm::​*:*"          //this one has hidden character
                    ]
                }
            ]
        };

        var processedIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["*:*"],
                    "ActionRegex": ["^([0-9A-Za-z]+)*:([0-9A-Za-z]+)*$"],
                    "Resource": [
                        "ssrn:ss:sm::​*:*"
                    ],
                    "ResourceRegex": [
                        "^ssrn:ss:sm::([0-9A-Za-z_]+/?)*:([0-9A-Za-z_]+/?)*$"
                    ]
                }
            ]
        };

        expect(iam.processIamData(sampleIam)).to.deep.equal(processedIam);
    });


});

describe('During IAM rule processing', function(){
    it('Processes each Resource into a Regular Expression', function(){

        var sampleIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["CanRead"],
                    "Resource": [
                        "ssrn:ss:iam:::account/100/assessmentgroup/*/customquestions"
                    ]
                }
            ]
        };

        var processedIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["CanRead"],
                    "ActionRegex": ["^CanRead$"],
                    "Resource": [
                        "ssrn:ss:iam:::account/100/assessmentgroup/*/customquestions"
                    ],
                    "ResourceRegex": [
                        "^ssrn:ss:iam:::account/100/assessmentgroup/([0-9A-Za-z_]+/?)*/customquestions$"
                    ]
                }
            ]
        };

        expect(iam.processIamData(sampleIam)).to.deep.equal(processedIam);
    });

    it('should successfully process without an array for actions.', function(){

        var sampleIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "CanRead",
                    "Resource": [
                        "ssrn:ss:iam:::account/100/assessmentgroup/*/customquestions"
                    ]
                }
            ]
        };

        var processedIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "CanRead",
                    "ActionRegex": ["^CanRead$"],
                    "Resource": [
                        "ssrn:ss:iam:::account/100/assessmentgroup/*/customquestions"
                    ],
                    "ResourceRegex": [
                        "^ssrn:ss:iam:::account/100/assessmentgroup/([0-9A-Za-z_]+/?)*/customquestions$"
                    ]
                }
            ]
        };

        expect(iam.processIamData(sampleIam)).to.deep.equal(processedIam);
    });

    it('should successfully process without an array for resource.', function(){

        var sampleIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "CanRead",
                    "Resource": "ssrn:ss:iam:::account/100/assessmentgroup/*/customquestions"
                }
            ]
        };

        var processedIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "CanRead",
                    "ActionRegex": ["^CanRead$"],
                    "Resource": "ssrn:ss:iam:::account/100/assessmentgroup/*/customquestions",
                    "ResourceRegex": [
                        "^ssrn:ss:iam:::account/100/assessmentgroup/([0-9A-Za-z_]+/?)*/customquestions$"
                    ]
                }
            ]
        };

        expect(iam.processIamData(sampleIam)).to.deep.equal(processedIam);
    });



});


describe('During authorization checks', function(){

    describe('should fail to grant permission', function(){

        it('due to the action being limited', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["CanRead"],
                        "Resource": [
                            "ssrn:ss:iam:::account/100/assessmentgroup/*/customquestions"
                        ]
                    }
                ]
            };


            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:iam:::account/100/assessmentgroup/2/customquestions', 'CanUpdate',processedIam)).to.equal(false);
        });

        it('due to the account not matching the accounts permitted', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["CanRead"],
                        "Resource": [
                            "ssrn:ss:iam:::account/100/assessmentgroup/*/customquestions"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:iam:::account/101/assessmentgroup/2/customquestions', 'CanRead',processedIam)).to.equal(false);
        });



    });

    describe('should successfully to grant permission', function(){

        it('with a wildcard authorization resource', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["sm:*"],
                        "Resource": [
                            "ssrn:ss:sm::608:*"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:sm:::search', 'sm:CanRead',processedIam)).to.equal(true);

            var result = iam.getActionCriteria('sm:CanRead', iam.processIamData(sampleIam));

            //console.log(result);


        });


        it('with a wildcard IAM resource', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["sm:CanRead"],
                        "Resource": [
                            "ssrn:ss:iam::100:assessmentgroup/*"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:iam::100:assessmentgroup/2', 'sm:CanRead',processedIam)).to.equal(true);
        });


        it('with a fixed resource', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["CanRead"],
                        "Resource": [
                            "ssrn:ss:iam::100:assessmentgroup/2"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:iam::100:assessmentgroup/2', 'CanRead',processedIam)).to.equal(true);
        });

        it('with a root level resource', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["CanRead"],
                        "Resource": [
                            "ssrn:ss:iam::100:*"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:iam::100:assessmentgroup/2', 'CanRead',processedIam)).to.equal(true);
        });

        it('with a root level resource and a wildcard at the end of the action.', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["Can*"],
                        "Resource": [
                            "ssrn:ss:iam::100:*"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:iam::100:assessmentgroup/2', 'CanRead',processedIam)).to.equal(true);
        });

        it('with a root level resource and a wildcard at the start of the action.', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["*Read"],
                        "Resource": [
                            "ssrn:ss:iam::100:*"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:iam::100:assessmentgroup/2', 'CanRead',processedIam)).to.equal(true);
        });

        it('with a root level resource and a wildcard at the start and end of the action.', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["*an*"],
                        "Resource": [
                            "ssrn:ss:iam::100:*"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:iam::100:assessmentgroup/2', 'CanRead',processedIam)).to.equal(true);
        });

        it('with a root level resource and a wildcard at the start of the action with multiple actions.', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["*Read", "CanView"],
                        "Resource": [
                            "ssrn:ss:iam::100:*"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:iam::100:assessmentgroup/2', 'CanRead',processedIam)).to.equal(true);
        });

        it('with multiple root level resource and a wildcard at the start of the action with multiple actions.', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["*Read", "CanView"],
                        "Resource": [
                            "ssrn:ss:iam::100:*",
                            "ssrn:ss:iam::200:*"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:iam::100:assessmentgroup/2', 'CanRead',processedIam)).to.equal(true);
            expect(iam.authorize('ssrn:ss:iam::200:assessmentgroup/2', 'CanView',processedIam)).to.equal(true);
        });


    });

    describe('should successfully to deny permission', function(){

        it('with a wildcard resource', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "ssrn:ss:iam::100:*"
                    },
                    {
                        "Effect": "Deny",
                        "Action": "CanRead",
                        "Resource": "ssrn:ss:iam::100:assessmentgroup/2"
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:iam::100:assessmentgroup/2', 'CanRead',processedIam)).to.equal(false);
        });


    });

});

describe('During gathering the action criteria', function(){

    it('should allow with general wildcards.', function(){
        var sampleIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["sm:*"],
                    "Resource": [
                        "ssrn:ss:sm::100:*"
                    ]
                }
            ]
        };

        var result = iam.getActionCriteria('sm:SearchResults', iam.processIamData(sampleIam));

        expect(result).to.have.all.keys(['100']);
        expect(result[100].Must).to.have.length(0);
        expect(result[100].MustNot).to.have.length(0);

    });

    it('should allow with an account level wildcard and a single resource deny.', function(){
        var sampleIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["sm:*"],
                    "Resource": [
                        "ssrn:ss:sm::100:*"
                    ]
                },
                {
                    "Effect": "Deny",
                    "Action": ["sm:*"],
                    "Resource": [
                        "ssrn:ss:sm::100:assessment/1500"
                    ]
                }
            ]
        };

        var result = iam.getActionCriteria('sm:SearchResults', iam.processIamData(sampleIam));

        expect(result).to.have.all.keys(['100']);
        expect(result[100].Must).to.have.length(0);
        expect(result[100].MustNot).to.have.length(1);
        expect(result[100].MustNot[0]).to.deep.equal({ "type": "assessment", "id": "1500" } );

    });

    it('should allow with multiple an account level wildcards and a single resource deny.', function(){
        var sampleIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["sm:*"],
                    "Resource": [
                        "ssrn:ss:sm::100:*",
                        "ssrn:ss:sm::200:*"
                    ]
                },
                {
                    "Effect": "Deny",
                    "Action": ["sm:*"],
                    "Resource": [
                        "ssrn:ss:sm::100:assessment/1500"
                    ]
                }
            ]
        };

        var result = iam.getActionCriteria('sm:SearchResults', iam.processIamData(sampleIam));

        expect(result).to.have.all.keys(['100','200']);
        expect(result[100].Must).to.have.length(0);
        expect(result[100].MustNot).to.have.length(1);
        expect(result[100].MustNot[0]).to.deep.equal({ "type": "assessment", "id": "1500" } );

        expect(result[200].Must).to.have.length(0);
        expect(result[200].MustNot).to.have.length(0);

    });


});