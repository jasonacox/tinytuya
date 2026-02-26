# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# Import from the local working directory
import os
import sys
sys.path.insert(0, os.path.abspath('../..'))

import tinytuya

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = tinytuya.__project__
copyright = tinytuya.__copyright__
author = tinytuya.__author__
release = tinytuya.__version__

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
   'sphinx.ext.duration',
   'sphinx.ext.doctest',
   'sphinx.ext.autodoc',
   'sphinx.ext.autosummary',
   'sphinx.ext.napoleon',
]

autosummary_generate = True
autosummary_imported_members = True
toc_object_entries = True

napoleon_numpy_docstring = False


templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

#html_theme = 'alabaster'
html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

autosummary_context = {
    'tinytuya_core_autodocument': tinytuya.document.sphinx_autodocument,
    'tinytuya_core_extradocument': tinytuya.document.sphinx_extradocument,
    'tinytuya_parent_modules': [
        {
            'group': 'Standard Device Modules',
            'template': 'autoclass-fake-module.rst',
            'members': [
                { 'name': 'tinytuya.Device', 'currentmodule': False },
                { 'name': 'tinytuya.BulbDevice', 'currentmodule': True },
                { 'name': 'tinytuya.OutletDevice', 'currentmodule': True },
                { 'name': 'tinytuya.CoverDevice', 'currentmodule': True },
            ],
        },
        {
            'group': 'Module Functions',
            'template': 'automodule-tinytuya.rst',
            'members': [
                { 'name': 'tinytuya' },
            ],
        }
    ]
}

#autosummary_skip_modules = ([ 'tinytuya.core.'+k for k in tinytuya.document.sphinx_autodocument.keys() ] +
#autosummary_skip_modules = ([ k.split('.')[-1] for k in autosummary_context['tinytuya_parent_modules'].keys() ] +
#                            ['Cloud'])
autosummary_skip_modules = ['tinytuya.Cloud']
for grp in autosummary_context['tinytuya_parent_modules']:
    for gmemb in grp['members']:
        autosummary_skip_modules.append( gmemb['name'] )

#print(autosummary_skip_modules)

def autodoc_skip_member_callback(app, what, name, obj, skip, options):
    #if( what == 'module'):
    #    print(what, name, getattr(obj, '__name__', ''), getattr(obj, '__module__', 'xz'))
    # skip classes that are displayed separately
    if( what == 'module' and getattr(obj, '__module__', '') in autosummary_skip_modules ):
        #print('Skipping:', name, skip, obj)
        return True  # Skip it
    return None  # Use default skipping behavior otherwise

def setup(app):
    app.connect("autodoc-skip-member", autodoc_skip_member_callback)
