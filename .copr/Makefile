srpm:
	dnf install -y git
	git config --global --add safe.directory ${PWD}
	./build.sh --with-timestamp --with-commit-id srpm
	if [[ "${outdir}" != "" ]]; then \
	    mv ${HOME}/build/tomcatjss/SRPMS/* ${outdir}; \
	fi
