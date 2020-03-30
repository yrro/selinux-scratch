project('se', 'c', default_options : ['c_std=c11'])
cc = meson.get_compiler('c')
selinux = cc.find_library('selinux')
executable('se', 'se.c', dependencies : selinux)
