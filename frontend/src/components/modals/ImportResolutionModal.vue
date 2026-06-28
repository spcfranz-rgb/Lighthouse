<template>
  <div class="modal fade show d-block" style="background: rgba(0,0,0,0.85)" tabindex="-1">
    <div class="modal-dialog modal-xl modal-dialog-centered modal-dialog-scrollable">
      <div class="modal-content border-secondary bg-dark text-light">
        <div class="modal-header border-secondary bg-dark">
          <h5 class="modal-title text-info">Merge Configuration</h5>
          <button type="button" class="btn-close btn-close-white" @click="$emit('close')"></button>
        </div>
        
        <div class="modal-body bg-body-tertiary">
          <div class="alert alert-info border-secondary py-2 small">
            <strong>Analysis Complete:</strong> Found {{ analysis.clean_inserts.length }} clean devices to append, and {{ analysis.conflicts.length }} conflicts requiring your attention.
          </div>

          <div v-if="analysis.clean_inserts.length > 0" class="mb-4">
            <h6 class="text-success border-bottom border-secondary pb-2">Ready to Append (No Conflicts)</h6>
            <div class="d-flex flex-wrap gap-2">
              <span v-for="(item, idx) in analysis.clean_inserts" :key="idx" class="badge bg-dark border border-secondary text-success">
                ➕ {{ item.data.name }} ({{ item.data.ip }})
              </span>
            </div>
          </div>

          <div v-if="analysis.conflicts.length > 0">
            <h6 class="text-danger border-bottom border-secondary pb-2 mb-3">Resolve Conflicts</h6>
            
            <div v-for="(conflict, index) in analysis.conflicts" :key="index" class="card bg-dark border-danger mb-3">
              <div class="card-header border-danger py-2 d-flex justify-content-between align-items-center">
                <span class="fw-bold text-danger">⚠️ {{ conflict.reasons.join(' | ') }}</span>
                <span class="badge bg-secondary">{{ conflict.type.toUpperCase() }}</span>
              </div>
              <div class="card-body p-0">
                <table class="table table-sm table-dark mb-0 align-middle">
                  <thead>
                    <tr>
                      <th class="ps-3 w-50">Current Database Target</th>
                      <th class="w-50">Imported Payload</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td class="ps-3 border-end border-secondary">
                        <div v-if="conflict.existing">
                          <div class="fw-bold">{{ conflict.existing.name }}</div>
                          <div class="text-muted small font-monospace">{{ conflict.existing.ip }}</div>
                        </div>
                        <div v-else class="text-muted small fst-italic">No direct target (Cross-table collision)</div>
                      </td>
                      <td>
                        <div class="fw-bold text-warning">{{ conflict.imported.name }}</div>
                        <div class="text-muted small font-monospace">{{ conflict.imported.ip }}</div>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <div class="card-footer border-danger bg-dark py-2">
                <div class="btn-group w-100 shadow-sm">
                  <input type="radio" class="btn-check" :name="`res-${index}`" :id="`skip-${index}`" value="skip" v-model="conflict.resolution">
                  <label class="btn btn-outline-secondary fw-bold" :for="`skip-${index}`">Skip (Keep Current)</label>

                  <input type="radio" class="btn-check" :name="`res-${index}`" :id="`overwrite-${index}`" value="overwrite" v-model="conflict.resolution">
                  <label class="btn btn-outline-danger fw-bold" :for="`overwrite-${index}`">Overwrite Target</label>
                </div>
              </div>
            </div>
          </div>
        </div>
        
        <div class="modal-footer border-secondary justify-content-between bg-dark">
          <button type="button" class="btn btn-outline-secondary" @click="$emit('close')">Cancel Merge</button>
          <button type="button" class="btn btn-info fw-bold px-4" @click="submitMerge" :disabled="processing">
            {{ processing ? 'Applying Changes...' : 'Execute Merge' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import axios from 'axios'
import { useSystemStore } from '../../stores/systemStore'

const props = defineProps(['analysis'])
const emit = defineEmits(['close', 'merged'])
const store = useSystemStore()
const processing = ref(false)

const submitMerge = async () => {
  processing.value = true
  try {
    const payload = {
      clean_inserts: props.analysis.clean_inserts,
      resolved_conflicts: props.analysis.conflicts
    }
    const response = await axios.post('/api/v1/system/import/apply', payload)
    
    if (response.data.success) {
      store.addToast('Configuration successfully merged.')
      await store.fetchSystemData() // Re-hydrate the app state instantly
      emit('merged')
    } else {
      store.addToast(response.data.message || 'Merge failed.', 'danger')
    }
  } catch (error) {
    store.addToast('Failed to apply merge resolution.', 'danger')
  } finally {
    processing.value = false
  }
}
</script>
