(function(){

    'use strict';

    var _ = require('lodash');

    // create a regex from a string
    function createRegExPattern (input)
    {
        input = '^' + input.replace('*','[0-9]+') + '$';
        return new RegExp(input);

    }

    // process iam file
    function processIamData( data ) {

        //var data = jsonfile.readFileSync(file);

        for (var i in data.Statement) {

            var stmt = data.Statement[i];

            stmt.ResourceRegex = [];
            if (_.has(stmt, 'Resource') && stmt.Resource instanceof  Array) {

                for (var j in stmt.Resource) {
                    stmt.ResourceRegex.push(createRegExPattern(stmt.Resource[j]));
                }
            }
            else {
                stmt.ResourceRegex.push(createRegExPattern(stmt.Resource));
            }

        }

        return data;
    }

    // processed json data as input
    function seperateStmts( stmts ) {

        var allowString = 'Allow';
        var denyString = 'Deny';

        var allowStmts = [];
        var denyStmts = [];

        for (var i in stmts) {

            var stmt = stmts[i];

            if (_.has(stmt, 'Effect'))
                if (stmt.Effect === allowString) {
                    allowStmts.push(stmt);
                }
                else if (stmt.Effect === denyString) {
                    denyStmts.push(stmt);
                }
        }

        return {
            denyStmts: denyStmts,
            allowStmts: allowStmts
        };

    }


    // authorize a resource for an action
    function authorize( resource, action, data ) {

        // seperate processed allow and deny stmts
        var stmts =  seperateStmts(data.Statement);


        // default deny
        var defaultDeny = false;

        // find denied action for the resource;
        if ( _.has( stmts, 'denyStmts') && findActionForResource( resource,  action, stmts.denyStmts )) {
            //action found in denied resource action
            return false;
        }


        if ( _.has( stmts, 'allowStmts') && findActionForResource( resource,  action, stmts.allowStmts )) {
            //action found in allowed resource action
            return true;
        }

        return defaultDeny;

    }


    function findActionForResource( resource, action, stmts ) {

        for (var i in stmts) {
            var stmt = stmts[i];

            for ( var j in stmt.ResourceRegex ) {

                var regex = stmt.ResourceRegex[j];
                //match found and stmt has Action
                if ( regex.test(resource)  && _.has(stmt,'Action')) {
                    var actions = stmt.Action;
                    //console.log('match found');
                    if( actions instanceof  Array ){

                        for( var k in actions ) {

                            if( actions[k] === action ){
                                return true;
                            }
                        }
                    }else {
                        if( actions === action ){
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }


    var iam = {
        processIamData: processIamData,
        authorize: authorize
    };

    module.exports = iam;

})();
