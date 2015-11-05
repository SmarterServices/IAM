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
                        "ssrn:ss:iam:::account/100/assestmentgroup/*/customquestions"
                    ]
                }
            ]
        };

        var processedIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["CanRead"],
                    "Resource": [
                        "ssrn:ss:iam:::account/100/assestmentgroup/*/customquestions"
                    ],
                    "ResourceRegex": [
                        "^ssrn:ss:iam:::account/100/assestmentgroup/([0-9A-Za-z]+/?)*/customquestions$"
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
                            "ssrn:ss:iam:::account/100/assestmentgroup/*/customquestions"
                        ]
                    }
                ]
            };


            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:iam:::account/100/assestmentgroup/2/customquestions', 'CanUpdate',processedIam)).to.equal(false);
        });

        it('due to the account not matching the accounts permitted', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["CanRead"],
                        "Resource": [
                            "ssrn:ss:iam:::account/100/assestmentgroup/*/customquestions"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:iam:::account/101/assestmentgroup/2/customquestions', 'CanRead',processedIam)).to.equal(false);
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
                            "ssrn:ss:iam:::account/100/assestmentgroup/*/customquestions"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:iam:::account/100/assestmentgroup/2/customquestions', 'CanRead',processedIam)).to.equal(true);
        });


        it('with a fixed resource', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["CanRead"],
                        "Resource": [
                            "ssrn:ss:iam:::account/100/assestmentgroup/2/customquestions"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('ssrn:ss:iam:::account/100/assestmentgroup/2/customquestions', 'CanRead',processedIam)).to.equal(true);
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

            expect(iam.authorize('ssrn:ss:iam:::account/100/assestmentgroup/2/customquestions', 'CanRead',processedIam)).to.equal(true);
        });

        it('with a root level resource and a wildcard action.', function(){

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

            expect(iam.authorize('ssrn:ss:iam:::account/100/assestmentgroup/2/customquestions', 'CanRead',processedIam)).to.equal(true);
        });

    });


});
