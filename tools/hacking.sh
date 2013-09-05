#!/bin/bash
flake8 barbicanclient | tee flake8.log
exit ${PIPESTATUS[0]}
