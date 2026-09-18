/**
 * CYBER TRIAGE TOOL - SIH1744
 * Vanilla JavaScript Interactive Engine
 * Handles triage pipeline inspection, keyboard accessibility, presentation mode & copy actions.
 */

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  // ==========================================================================
  // 1. DOM Elements
  // ==========================================================================
  const processSteps = document.querySelectorAll('.process-step');
  const detailStepBadge = document.getElementById('detailStepBadge');
  const detailTitle = document.getElementById('detailTitle');
  const detailDesc = document.getElementById('detailDesc');
  const detailArtifacts = document.getElementById('detailArtifacts');
  const detailPanel = document.getElementById('processDetailPanel');
  const copyIdBtn = document.getElementById('copyIdBtn');
  const presentationModeBtn = document.getElementById('presentationModeBtn');
  const toastNotification = document.getElementById('toastNotification');

  let activeStepIndex = 0;
  let toastTimer = null;

  // ==========================================================================
  // 2. Stage Inspector Logic
  // ==========================================================================
  /**
   * Updates the active triage stage and updates the detail panel.
   * @param {HTMLElement} stepElement - The clicked or hovered process step button.
   */
  function activateStep(stepElement) {
    if (!stepElement) return;

    processSteps.forEach((btn, idx) => {
      const isActive = btn === stepElement;
      btn.classList.toggle('active', isActive);
      btn.setAttribute('aria-current', isActive ? 'step' : 'false');
      if (isActive) {
        activeStepIndex = idx;
      }
    });

    const stepNum = stepElement.getAttribute('data-step') || '01';
    const title = stepElement.getAttribute('data-title') || '';
    const desc = stepElement.getAttribute('data-desc') || '';
    const artifacts = stepElement.getAttribute('data-artifacts') || '';

    if (detailStepBadge) detailStepBadge.textContent = `STAGE 0${stepNum}`;
    if (detailTitle) detailTitle.textContent = title;
    if (detailDesc) detailDesc.textContent = desc;
    if (detailArtifacts) detailArtifacts.textContent = artifacts;

    if (detailPanel) {
      detailPanel.style.borderColor = 'var(--color-accent-red-border)';
      setTimeout(() => {
        detailPanel.style.borderColor = 'var(--border-subtle)';
      }, 300);
    }
  }

  // Attach hover & click listeners to process steps
  processSteps.forEach((step) => {
    step.addEventListener('click', () => {
      activateStep(step);
    });

    step.addEventListener('mouseenter', () => {
      activateStep(step);
    });

    step.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        activateStep(step);
      }
    });
  });

  // ==========================================================================
  // 3. Problem Statement Copy Handler
  // ==========================================================================
  function showToast(message) {
    if (!toastNotification) return;

    toastNotification.textContent = message;
    toastNotification.classList.add('show');

    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      toastNotification.classList.remove('show');
    }, 2200);
  }

  if (copyIdBtn) {
    copyIdBtn.addEventListener('click', async () => {
      const textToCopy = 'SIH1744';
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(textToCopy);
        } else {
          // Fallback for non-HTTPS or unsupported environments
          const textArea = document.createElement('textarea');
          textArea.value = textToCopy;
          textArea.style.position = 'fixed';
          textArea.style.opacity = '0';
          document.body.appendChild(textArea);
          textArea.select();
          document.execCommand('copy');
          document.body.removeChild(textArea);
        }
        showToast('COPIED ID: SIH1744');
      } catch (err) {
        console.warn('Clipboard copy failed:', err);
        showToast('ID: SIH1744');
      }
    });
  }

  // ==========================================================================
  // 4. Fullscreen / Presentation View Toggle
  // ==========================================================================
  function togglePresentationMode() {
    document.body.classList.toggle('presentation-mode');
    const isPresentation = document.body.classList.contains('presentation-mode');

    if (presentationModeBtn) {
      const labelSpan = presentationModeBtn.querySelector('span:last-child');
      if (labelSpan) {
        labelSpan.textContent = isPresentation ? 'EXIT PRESENTATION' : 'PRESENTATION VIEW';
      }
    }

    showToast(isPresentation ? 'PRESENTATION MODE ACTIVE' : 'STANDARD VIEW RESTORED');
  }

  if (presentationModeBtn) {
    presentationModeBtn.addEventListener('click', togglePresentationMode);
  }

  // ==========================================================================
  // 5. Global Keyboard Navigation
  // ==========================================================================
  document.addEventListener('keydown', (e) => {
    // Ignore keystrokes inside input fields if any exist
    if (['INPUT', 'TEXTAREA'].includes(e.target.tagName)) return;

    // Number keys 1-6 map to pipeline stages
    const keyNum = parseInt(e.key, 10);
    if (keyNum >= 1 && keyNum <= processSteps.length) {
      const targetStep = processSteps[keyNum - 1];
      if (targetStep) {
        activateStep(targetStep);
        targetStep.focus();
      }
    }

    // P key toggles Presentation Mode
    if (e.key === 'p' || e.key === 'P') {
      togglePresentationMode();
    }

    // Arrow Left / Right navigation between steps
    if (e.key === 'ArrowRight') {
      const nextIndex = (activeStepIndex + 1) % processSteps.length;
      activateStep(processSteps[nextIndex]);
      processSteps[nextIndex].focus();
    } else if (e.key === 'ArrowLeft') {
      const prevIndex = (activeStepIndex - 1 + processSteps.length) % processSteps.length;
      activateStep(processSteps[prevIndex]);
      processSteps[prevIndex].focus();
    }
  });

  // Log system initialization
  console.log('[Cyber Triage System] SIH1744 Engine Initialized.');
});
