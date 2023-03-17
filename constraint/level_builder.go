package constraint

// set the level of a variable which depends on lazy wire. We only set if it
// isn't solve through other means.
func (system *System) setLazyDependentVariableLevel(wireID int, dependentLevel int) {
	// 1. if it is in active list, then return early
	// 2. if it is already set, then return
	// 3. finally, update in the map to dependentLevel + 1

	if _, ok := system.lbActiveWireLevels[wireID]; ok {
		return
	}
	if _, ok := system.lbLazyWireLevels[wireID]; ok {
		return
	}
	system.lbLazyWireLevels[wireID] = dependentLevel + 1
}

func (system *System) setActiveDependentVariableLevel(wireID int, dependentLevel int) {
	// 1. if wire ID is in witness, then return early
	// 2. if it is already set, then return
	// 3. finally update in the map to dependentLevel + 1

	if wireID < system.GetNbPublicVariables()+system.GetNbSecretVariables() {
		return // ignore inputs
	}
	if _, ok := system.lbActiveWireLevels[wireID]; ok {
		return
	}
	system.lbActiveWireLevels[wireID] = dependentLevel + 1
}

// The main idea here is to find a naive clustering of independent constraints
// that can be solved in parallel.
//
// We know that at each constraint, we will have at most one unsolved wire. (a
// constraint may have no unsolved wire in which case it is a plain check that
// the constraint hold, or it may additionally have some wires that will be
// solved by solver hints)
//
// We build a graph of dependency; we say that a wire is solved at a level l:
//
//	l = max(level_of_dependencies(wire)) + 1
//
// But we keep in mind that the wire may depend on lazy wire. In that case we
// set it's lazy level similarly. The lazy wires must be shifted later when all
// the dependencies are activated.
func (system *System) updateLevel(cID int, c Iterable) {
	// Strategy:
	//   1. get the maximum level of the lazy wires
	//   2. if it is >= 0, then this means that we depend on lazy constraint. We cannot set the solving levels of the constraint here.
	//      - update the lazy wire level map using setLazyDependentVariable
	//      - update the constraint dependency map
	//      - return out of this method
	//   3. we are not dependent on the lazy wires. First get the maximum level of the dependent wire
	//      - now, update the map of active wires with maximum depenent level + 1
	//      - also update the constraint level map
	//   4. update the all active wire to be level -1 in lazy wires

	iterator := c.WireIterator()
	maxActiveLevel, maxLazyLevel := -1, -1

	for wID := iterator(); wID != -1; wID = iterator() {
		itActiveDepLevel, itLazyDepLevel := system.processWire(wID)
		if itActiveDepLevel > maxActiveLevel {
			maxActiveLevel = itActiveDepLevel
		}
		if itLazyDepLevel > maxLazyLevel {
			maxLazyLevel = itLazyDepLevel
		}
	}
	if maxLazyLevel >= 0 {
		for _, wireID := range system.lbOutputs {
			system.setLazyDependentVariableLevel(wireID, maxLazyLevel)
		}
		if len(system.lazyLevels) <= maxLazyLevel {
			system.lazyLevels = append(system.lazyLevels, nil)
		}
		system.lazyLevels[maxLazyLevel] = append(system.lazyLevels[maxLazyLevel], cID)
	} else {
		for _, wireID := range system.lbOutputs {
			system.setActiveDependentVariableLevel(wireID, maxActiveLevel)
		}
		if len(system.Levels) <= (maxActiveLevel + 1) {
			system.Levels = append(system.Levels, nil)
		}
		system.Levels[maxActiveLevel+1] = append(system.Levels[maxActiveLevel+1], cID)
	}
	system.lbOutputs = system.lbOutputs[:0]
	system.lbHints = map[int]struct{}{}
}

func (system *System) processWire(wireID int) (maxDepActiveLevel, maxDepLazyLevel int) {
	if wireID < system.GetNbPublicVariables()+system.GetNbSecretVariables() {
		// ignore inputs. They are always known
		return -1, -1
	}
	if level, ok := system.lbActiveWireLevels[wireID]; ok {
		// this wire is already known as active. Return its level
		return level, -1
	}
	if level, ok := system.lbLazyWireLevels[wireID]; ok {
		// this wire is already known as lazy. Return its level
		return -1, level
	}
	// we don't know how to solve this wire; it's either THE wire we have to solve or a hint.
	if hID, ok := system.MHints[wireID]; ok {
		// check that we didn't process that hint already; performance wise, if many wires in a
		// constraint are the output of the same hint, and input to parent hint are themselves
		// computed with a hint, we can suffer.
		// (nominal case: not too many different hints involved for a single constraint)
		if _, ok := system.lbHints[hID]; ok {
			// we have run the hint already once and set the maximum level for
			// another wire. It is safe to return small here because we take max
			return -1, -1
		}
		system.lbHints[hID] = struct{}{}
		h := &system.HintMappings[hID]
		system.lbOutputs = append(system.lbOutputs, h.Outputs...)
		// get the maximum level of the inputs of the hint
		maxActiveLevel, maxLazyLevel := -1, -1
		for _, in := range h.Inputs {
			for _, t := range in {
				if !t.IsConstant() {
					recActiveLevel, recLazyLevel := system.processWire(int(t.VID))
					if recActiveLevel > maxActiveLevel {
						maxActiveLevel = recActiveLevel
					}
					if recLazyLevel > maxLazyLevel {
						maxLazyLevel = recLazyLevel
					}
				}
			}
		}
		return maxActiveLevel, maxLazyLevel
	}

	// it's the missing wire
	system.lbOutputs = append(system.lbOutputs, wireID)
	// we can return small value here. Because this is the output wire then it
	// will be set maximum+1 of the other wires.
	return -1, -1
}
