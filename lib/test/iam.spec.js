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
                        "^ssrn:ss:iam:::account/100/assessmentgroup/([0-9A-Za-z]+/?)*/customquestions$"
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
                        "^ssrn:ss:iam:::account/100/assessmentgroup/([0-9A-Za-z]+/?)*/customquestions$"
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
                        "^ssrn:ss:iam:::account/100/assessmentgroup/([0-9A-Za-z]+/?)*/customquestions$"
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
                        "^ssrn:ss:iam:::account/100/assessmentgroup/([0-9A-Za-z]+/?)*/customquestions$"
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

        it('with a wildcard resource', function(){

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

            expect(iam.authorize('ssrn:ss:iam:::account/100/assessmentgroup/2/customquestions', 'CanRead',processedIam)).to.equal(true);
        });


        it('with a fixed resource', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["CanRead"],
                        "Resource": [
                            "ssrn:ss:iam:::account/100/assessmentgroup/2/customquestions"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:iam:::account/100/assessmentgroup/2/customquestions', 'CanRead',processedIam)).to.equal(true);
        });

        it('with a root level resource', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["CanRead"],
                        "Resource": [
                            "ssrn:ss:iam:::account/100/*"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:iam:::account/100/assessmentgroup/2/customquestions', 'CanRead',processedIam)).to.equal(true);
        });

        it('with a root level resource and a wildcard at the end of the action.', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["Can*"],
                        "Resource": [
                            "ssrn:ss:iam:::account/100/*"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:iam:::account/100/assessmentgroup/2/customquestions', 'CanRead',processedIam)).to.equal(true);
        });

        it('with a root level resource and a wildcard at the start of the action.', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["*Read"],
                        "Resource": [
                            "ssrn:ss:iam:::account/100/*"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:iam:::account/100/assessmentgroup/2/customquestions', 'CanRead',processedIam)).to.equal(true);
        });

        it('with a root level resource and a wildcard at the start and end of the action.', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["*an*"],
                        "Resource": [
                            "ssrn:ss:iam:::account/100/*"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:iam:::account/100/assessmentgroup/2/customquestions', 'CanRead',processedIam)).to.equal(true);
        });

        it('with a root level resource and a wildcard at the start of the action with multiple actions.', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["*Read", "CanView"],
                        "Resource": [
                            "ssrn:ss:iam:::account/100/*"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:iam:::account/100/assessmentgroup/2/customquestions', 'CanRead',processedIam)).to.equal(true);
        });

        it('with multiple root level resource and a wildcard at the start of the action with multiple actions.', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["*Read", "CanView"],
                        "Resource": [
                            "ssrn:ss:iam:::account/100/*",
                            "ssrn:ss:iam:::account/200/*"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:iam:::account/100/assessmentgroup/2/customquestions', 'CanRead',processedIam)).to.equal(true);
            expect(iam.authorize('ssrn:ss:iam:::account/200/assessmentgroup/2/customquestions', 'CanView',processedIam)).to.equal(true);
        });


    });

    describe('should successfully to deny permission', function(){

        it('with a wildcard resource', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "ssrn:ss:iam:::account/100/*"
                    },
                    {
                        "Effect": "Deny",
                        "Action": "CanRead",
                        "Resource": "ssrn:ss:iam:::account/100/assessmentgroup/2/*"
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:iam:::account/100/assessmentgroup/2/customquestions', 'CanRead',processedIam)).to.equal(false);
        });


    });


});
