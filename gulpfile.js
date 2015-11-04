'use strict';

// Require and load our packages
var gulp = require('gulp'),
    mocha = require('gulp-mocha'),
    istanbul = require('gulp-istanbul'),
    util = require('gulp-util'),
    taskListing = require('gulp-task-listing'),
    jshint = require('gulp-jshint');


var paths = {
    lib: {
        src:['./lib/*.js'],
        specs: ['./lib/test/*.spec.js']
    }
};

gulp.task('help', taskListing );

gulp.task('default', ['help'] );

gulp.task('lint', function() {
    log('Analyzing source with JSHint');
    return gulp.src(paths.lib.src)
        .pipe(jshint())
        .pipe(jshint.reporter('jshint-stylish', {verbose: true}))
        .pipe(jshint.reporter('fail'));
});


gulp.task('tests', function (cb) {
    log('Running Tests')
    gulp.src('lib/*.js')
        .pipe(istanbul()) // Covering files
        .pipe(istanbul.hookRequire()) // Force `require` to return covered files

        .on('finish', function () {
            gulp.src(paths.lib.specs)
                .pipe(mocha({reporter: 'spec', timeout: 5000}))
                .pipe(istanbul.writeReports()) // Creating the reports after tests run
                .on('end', function () {
                    process.exit();
                });
        });
});

function log(msg){
    if (typeof(msg) === 'object') {
        for (var item in msg) {
            if (msg.hasOwnProperty('item')) {
                util.log(util.log(util.colors.blue(msg[item])));
            }
        }
    }
    else {
        util.log(util.colors.blue(msg));
    }
}
