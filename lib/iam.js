(function(){

    'use strict';

    var _ = require('lodash');

    // create a regex from a string
    function createRegExPatternForResource (input)
    {
        var parts = input.split('*');
        var new_parts = [];
        var p;
        var replace_string = '([0-9A-Za-z]+/?)*';
        for(p=0; p < parts.length; p++){
            if(p === 0 && !parts[p].length) {
                new_parts.push(replace_string);
            }else if(p < parts.length-1 && parts[p].length){
                new_parts.push(parts[p] + replace_string);
            }else if(p === parts.length-1 && parts[p].length){
                new_parts.push(parts[p]);
            }
        }

        return '^' + new_parts.join('') + '$';

    }

    function createRegExPatternForAction (input)
    {
        var parts = input.split('*');
        var new_parts = [];
        var p;
        for(p=0; p < parts.length; p++){
            if(!parts[p].length){
                new_parts.push('([0-9A-Za-z]+)*');
            }else{
                new_parts.push(parts[p]);
            }
        }

        return '^' + new_parts.join('') + '$';

    }

    // process iam file
    function processIamData( data ) {

        for (var i in data.Statement) {

            var stmt = data.Statement[i];

            stmt.ResourceRegex = [];
            if (_.has(stmt, 'Resource') && stmt.Resource instanceof  Array) {

                for (var j in stmt.Resource) {
                    stmt.ResourceRegex.push(createRegExPatternForResource(stmt.Resource[j]));
                }
            }
            else {
                stmt.ResourceRegex.push(createRegExPatternForResource(stmt.Resource));
            }

            stmt.ActionRegex = [];
            if (_.has(stmt, 'Action') && stmt.Action instanceof  Array) {

                for (var j in stmt.Action) {
                    stmt.ActionRegex.push(createRegExPatternForAction(stmt.Action[j]));
                }
            }
            else {
                stmt.ActionRegex.push(createRegExPatternForAction(stmt.Action));
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

                var regex = new RegExp(stmt.ResourceRegex[j]);
                //match found and stmt has Action
                if ( regex.test(resource)  && _.has(stmt,'ActionRegex')) {
                    var actions = stmt.ActionRegex;
                    if( actions instanceof  Array ){

                        for( var k in actions ) {
                            if( new RegExp(actions[k]).test(action) ){
                                return true;
                            }
                        }
                    }else {
                        if( new RegExp(actions).test(action) ){
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
