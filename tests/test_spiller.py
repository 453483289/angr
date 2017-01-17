import angr
import ana

def test_palindrome2():
    ana.set_dl(ana.DictDataLayer())

    p = angr.Project('/home/yans/code/angr/binaries-private/cgc_scored_event_2/cgc/0b32aa01_01')
    pg = p.factory.path_group()
    pg.active[0].state.options.discard('LAZY_SOLVES')
    limiter = angr.exploration_techniques.LengthLimiter(max_length=250)
    pg.use_technique(limiter)

    def pickle_callback(path): path.info['pickled'] = True
    def unpickle_callback(path): path.info['unpickled'] = True
    spiller = angr.exploration_techniques.Spiller(pickle_callback=pickle_callback, unpickle_callback=unpickle_callback)
    pg.use_technique(spiller)
    #pg.step(until=lambda lpg: len(lpg.active) == 10)
    #pg.step(until=lambda lpg: len(lpg.spill_stage) > 15)
    #pg.step(until=lambda lpg: spiller._pickled_paths)
    pg.run()
    assert spiller._ever_pickled > 0
    assert spiller._ever_unpickled == spiller._ever_pickled
    assert all(('pickled' not in path.info and 'unpickled' not in path.info) or (path.info['pickled'] and path.info['unpickled']) for path in pg.cut)
